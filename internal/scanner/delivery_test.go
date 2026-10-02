package scanner

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"cafe-scanner-tls/pkg/nats"
	"cafe-scanner-tls/pkg/scan"

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
	base := NewBaseScanner(nil, nats.SubjectScanRequestedTLS, nats.DurableScannerTLS, "TLS", func([]byte, bool) error {
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
	base := NewBaseScanner(nil, nats.SubjectScanRequestedTLS, nats.DurableScannerTLS, "TLS", func([]byte, bool) error {
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

type fakeConn struct {
	mu       sync.Mutex
	subjects []string
}

func (f *fakeConn) Publish(subject string, _ []byte) error {
	f.mu.Lock()
	f.subjects = append(f.subjects, subject)
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
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.subjects {
		if s == subject {
			return true
		}
	}
	return false
}

type stubPlugin struct {
	runs   int
	runErr error
}

func (s *stubPlugin) Descriptor() *scan.PluginDescriptor {
	return &scan.PluginDescriptor{Kind: scan.KindTLS, Subject: nats.SubjectScanRequestedTLS}
}
func (s *stubPlugin) DecodeHTTP([]byte) (scan.ScanTarget, error) { return nil, nil }
func (s *stubPlugin) DecodeMessage(any) (scan.ScanTarget, error) { return nil, nil }
func (s *stubPlugin) Run(context.Context, *uuid.UUID, scan.ScanTarget, scan.RunOptions) (scan.ScanResult, error) {
	s.runs++
	if s.runErr != nil {
		return nil, s.runErr
	}
	return nil, nil
}

func tlsPayload(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(nats.TLSScanMessage{
		ScanID:   uuid.New(),
		UserID:   uuid.New(),
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
	if conn.has(nats.SubjectScanFailed) {
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
	if !conn.has(nats.SubjectScanFailed) {
		t.Fatal("scan.failed was not published")
	}
	if conn.has(nats.SubjectScanCompleted) {
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
	if !conn.has(nats.SubjectScanCompleted) {
		t.Fatal("scan.completed was not published")
	}
	if conn.has(nats.SubjectScanFailed) {
		t.Fatal("scan.failed published on success")
	}
}
