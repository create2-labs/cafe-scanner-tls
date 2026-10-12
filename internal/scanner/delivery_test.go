package scanner

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"cafe-scanner-tls/pkg/nats"
	"cafe-scanner-tls/pkg/scan"

	lifecyclev1 "github.com/create2-labs/cafe-contracts/discovery/scanlifecycle/v1"
	requestv1 "github.com/create2-labs/cafe-contracts/discovery/scanrequest/v1"
	"github.com/google/uuid"
	natslib "github.com/nats-io/nats.go"
)

func TestWorkGate_RedeliveryAfterSettleDoesNotStart(t *testing.T) {
	g := newWorkGate()
	if got := g.Begin("scan"); got != decisionStart {
		t.Fatalf("first = %v", got)
	}
	g.Finish("scan", true)
	if got := g.Begin("scan"); got != decisionAck {
		t.Fatalf("redelivery = %v, want ack", got)
	}
}

func TestWorkGate_InFlightRedeliveryWaits(t *testing.T) {
	g := newWorkGate()
	if got := g.Begin("scan"); got != decisionStart {
		t.Fatalf("first = %v", got)
	}
	if got := g.Begin("scan"); got != decisionBusy {
		t.Fatalf("in flight = %v, want busy", got)
	}
	g.Finish("scan", false)
	if got := g.Begin("scan"); got != decisionStart {
		t.Fatalf("after failure = %v, want start", got)
	}
}

type fakeMsg struct {
	mu         sync.Mutex
	data       []byte
	delivered  uint64
	seq        uint64
	acks       int
	naks       int
	progresses int
}

func (m *fakeMsg) Data() []byte { return m.data }
func (m *fakeMsg) NumDelivered() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.delivered
}
func (m *fakeMsg) Sequence() uint64 { return m.seq }
func (m *fakeMsg) Ack() error {
	m.mu.Lock()
	m.acks++
	m.mu.Unlock()
	return nil
}
func (m *fakeMsg) Nak() error {
	m.mu.Lock()
	m.naks++
	m.mu.Unlock()
	return nil
}
func (m *fakeMsg) InProgress() error {
	m.mu.Lock()
	m.progresses++
	m.mu.Unlock()
	return nil
}

func (m *fakeMsg) ackCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acks
}

func (m *fakeMsg) nakCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.naks
}

func waitCount(t *testing.T, got func() int, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("count = %d, want >= %d", got(), want)
}

func TestBaseScanner_RedeliveryDoesNotRunTwice(t *testing.T) {
	var runs int
	var mu sync.Mutex
	base := NewBaseScanner(nil, requestv1.SubjectScanRequestedTLS, nats.DurableScannerTLS, "TLS", func([]byte, bool) error {
		mu.Lock()
		runs++
		mu.Unlock()
		return nil
	})
	scanID := uuid.New()
	payload, _ := json.Marshal(map[string]string{"scan_id": scanID.String()})
	msg := &fakeMsg{data: payload, delivered: 1, seq: 1}

	base.onMessage(msg)
	waitCount(t, msg.ackCount, 1)
	base.onMessage(msg)
	waitCount(t, msg.ackCount, 2)

	mu.Lock()
	defer mu.Unlock()
	if runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
}

func TestBaseScanner_FailureNacksUntilLast(t *testing.T) {
	base := NewBaseScanner(nil, requestv1.SubjectScanRequestedTLS, nats.DurableScannerTLS, "TLS", func([]byte, bool) error {
		return errTest
	})
	payload, _ := json.Marshal(map[string]string{"scan_id": uuid.New().String()})
	msg := &fakeMsg{data: payload, delivered: 1, seq: 7}
	base.onMessage(msg)
	waitCount(t, msg.nakCount, 1)
	if msg.ackCount() != 0 {
		t.Fatalf("acks = %d, want 0", msg.ackCount())
	}
}

type errTestType struct{}

func (errTestType) Error() string { return "scan failed" }

var errTest error = errTestType{}

type published struct {
	subject string
	data    []byte
}

type fakeConn struct {
	mu   sync.Mutex
	pubs []published
}

func (f *fakeConn) Publish(subject string, data []byte) error {
	f.mu.Lock()
	f.pubs = append(f.pubs, published{subject: subject, data: append([]byte(nil), data...)})
	f.mu.Unlock()
	return nil
}
func (f *fakeConn) Subscribe(string, func(*natslib.Msg)) (*natslib.Subscription, error) {
	return nil, nil
}
func (f *fakeConn) ConsumeDurable(context.Context, string, string, func(nats.DurableMessage)) error {
	return nil
}
func (f *fakeConn) Close()            {}
func (f *fakeConn) IsConnected() bool { return true }

func (f *fakeConn) has(subject string) bool {
	return f.body(subject) != nil
}

func (f *fakeConn) body(subject string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, pub := range f.pubs {
		if pub.subject == subject {
			return pub.data
		}
	}
	return nil
}

func (f *fakeConn) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pubs)
}

type stubPlugin struct {
	runs   int
	runErr error
	result scan.ScanResult
}

func (s *stubPlugin) Descriptor() *scan.PluginDescriptor {
	return &scan.PluginDescriptor{Kind: scan.KindTLS, Subject: requestv1.SubjectScanRequestedTLS}
}
func (s *stubPlugin) DecodeHTTP([]byte) (scan.ScanTarget, error) { return nil, nil }
func (s *stubPlugin) DecodeMessage(any) (scan.ScanTarget, error) { return nil, nil }
func (s *stubPlugin) Run(context.Context, *uuid.UUID, scan.ScanTarget, scan.RunOptions) (scan.ScanResult, error) {
	s.runs++
	if s.runErr != nil {
		return nil, s.runErr
	}
	return s.result, nil
}

type fixedRaw struct{ value any }

func (fixedRaw) ScanKind() string                { return scan.KindTLS }
func (fixedRaw) ScannedAt() time.Time            { return time.Time{} }
func (fixedRaw) Findings() []scan.Finding        { return nil }
func (fixedRaw) Classification() string          { return "" }
func (fixedRaw) ToCBOM() (map[string]any, error) { return nil, nil }
func (f fixedRaw) Raw() any                      { return f.value }

func tlsPayload(t *testing.T) []byte {
	t.Helper()
	return tlsPayloadIDs(t, uuid.New().String(), uuid.New().String())
}

func tlsPayloadIDs(t *testing.T, scanID, userID string) []byte {
	t.Helper()
	b, err := json.Marshal(requestv1.TLS{
		ScanID:   scanID,
		UserID:   userID,
		Endpoint: "https://example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTLSDelivery_RetryKeepsCredit(t *testing.T) {
	conn := &fakeConn{}
	plugin := &stubPlugin{runErr: errTest}
	w := NewTLSScanner(plugin, conn)
	if err := w.handleDelivery(tlsPayload(t), false); err == nil {
		t.Fatal("expected retry error")
	}
	if plugin.runs != 1 {
		t.Fatalf("runs = %d, want 1", plugin.runs)
	}
	if conn.has(lifecyclev1.SubjectScanFailed) {
		t.Fatal("scan.failed published before the last delivery")
	}
}

func TestTLSDelivery_LastDeliveryPublishesFailed(t *testing.T) {
	conn := &fakeConn{}
	plugin := &stubPlugin{runErr: errTest}
	w := NewTLSScanner(plugin, conn)
	if err := w.handleDelivery(tlsPayload(t), true); err != nil {
		t.Fatal(err)
	}
	if lifecyclev1.SubjectScanFailed != "scan.failed" {
		t.Fatalf("subject = %s", lifecyclev1.SubjectScanFailed)
	}
	failed, err := lifecyclev1.DecodeFailed(conn.body(lifecyclev1.SubjectScanFailed))
	if err != nil {
		t.Fatal(err)
	}
	if failed.Kind != scan.KindTLS || failed.Endpoint != "https://example.com" || failed.Error == "" {
		t.Fatalf("failed = %#v", failed)
	}
	if conn.has(lifecyclev1.SubjectScanCompleted) {
		t.Fatal("scan.completed published on failure")
	}
}

func TestTLSDelivery_SuccessPublishesCompleted(t *testing.T) {
	conn := &fakeConn{}
	plugin := &stubPlugin{}
	w := NewTLSScanner(plugin, conn)
	if err := w.handleDelivery(tlsPayload(t), false); err != nil {
		t.Fatal(err)
	}
	if plugin.runs != 1 {
		t.Fatalf("runs = %d, want 1", plugin.runs)
	}
	if lifecyclev1.SubjectScanStarted != "scan.started" || lifecyclev1.SubjectScanCompleted != "scan.completed" {
		t.Fatalf("started %s completed %s", lifecyclev1.SubjectScanStarted, lifecyclev1.SubjectScanCompleted)
	}
	started, err := lifecyclev1.DecodeStarted(conn.body(lifecyclev1.SubjectScanStarted))
	if err != nil {
		t.Fatal(err)
	}
	completed, err := lifecyclev1.DecodeCompleted(conn.body(lifecyclev1.SubjectScanCompleted))
	if err != nil {
		t.Fatal(err)
	}
	if started.ScanID != completed.ScanID || started.Kind != scan.KindTLS || completed.Endpoint != "https://example.com" {
		t.Fatalf("started %#v completed %#v", started, completed)
	}
	if len(completed.Result) != 0 {
		t.Fatalf("result = %s", completed.Result)
	}
	if conn.has(lifecyclev1.SubjectScanFailed) {
		t.Fatal("scan.failed published on success")
	}
}

func TestTLSDelivery_InvalidRequestPublishesNothing(t *testing.T) {
	conn := &fakeConn{}
	plugin := &stubPlugin{}
	w := NewTLSScanner(plugin, conn)
	if err := w.handleDelivery([]byte("{"), false); err != nil {
		t.Fatal(err)
	}
	if plugin.runs != 0 || conn.count() != 0 {
		t.Fatalf("runs = %d pubs = %d", plugin.runs, conn.count())
	}
}

func TestTLSDelivery_CompletedKeepsResultJSON(t *testing.T) {
	conn := &fakeConn{}
	plugin := &stubPlugin{result: fixedRaw{value: map[string]any{"host": "example.com", "port": 443}}}
	w := NewTLSScanner(plugin, conn)
	if err := w.handleDelivery(tlsPayload(t), false); err != nil {
		t.Fatal(err)
	}
	completed, err := lifecyclev1.DecodeCompleted(conn.body(lifecyclev1.SubjectScanCompleted))
	if err != nil {
		t.Fatal(err)
	}
	if string(completed.Result) != `{"host":"example.com","port":443}` {
		t.Fatalf("result = %s", completed.Result)
	}
}

func TestTLSDelivery_NilScanIDIsReplaced(t *testing.T) {
	conn := &fakeConn{}
	w := NewTLSScanner(&stubPlugin{}, conn)
	payload := tlsPayloadIDs(t, requestv1.NilID, requestv1.NilID)
	if err := w.handleDelivery(payload, false); err != nil {
		t.Fatal(err)
	}
	started, err := lifecyclev1.DecodeStarted(conn.body(lifecyclev1.SubjectScanStarted))
	if err != nil {
		t.Fatal(err)
	}
	if started.ScanID == requestv1.NilID || started.UserID != requestv1.NilID {
		t.Fatalf("started = %#v", started)
	}
}
