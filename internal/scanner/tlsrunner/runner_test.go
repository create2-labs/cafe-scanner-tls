package tlsrunner

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"cafe-scanner-tls/internal/scanner/core"
	"cafe-scanner-tls/pkg/nats"

	heartbeatv1 "github.com/create2-labs/cafe-contracts/discovery/scannerheartbeat/v1"
	presencev1 "github.com/create2-labs/cafe-contracts/discovery/scannerpresence/v1"
	requestv1 "github.com/create2-labs/cafe-contracts/discovery/scanrequest/v1"
	natslib "github.com/nats-io/nats.go"
)

func TestStartAnnouncesTLSPresenceWithSharedContract(t *testing.T) {
	heartbeatInterval = time.Hour
	t.Cleanup(func() { heartbeatInterval = 30 * time.Second })

	if presencev1.Subject != "cafe.discovery.scanners.presence" {
		t.Fatalf("subject = %s", presencev1.Subject)
	}

	conn := &recordingConn{}
	_, shutdown, err := Runner{}.Start(context.Background(), &core.Deps{NATS: conn})
	if err != nil {
		t.Fatal(err)
	}
	shutdown()

	pubs := conn.publications()
	if len(pubs) != 2 {
		t.Fatalf("publications = %d, want joined then left", len(pubs))
	}
	joined := decodePresence(t, pubs[0])
	if pubs[0].subject != presencev1.Subject {
		t.Fatalf("subject = %s", pubs[0].subject)
	}
	if joined.Event != presencev1.EventJoined || joined.Type != "tls" || joined.ScannerID == "" {
		t.Fatalf("joined = %#v", joined)
	}
	assertPresenceJSON(t, pubs[0].data, presencev1.EventJoined, joined.ScannerID)

	left := decodePresence(t, pubs[1])
	if pubs[1].subject != presencev1.Subject {
		t.Fatalf("subject = %s", pubs[1].subject)
	}
	if left.Event != presencev1.EventLeft || left.ScannerID != joined.ScannerID || left.Type != "tls" {
		t.Fatalf("left = %#v joined id %s", left, joined.ScannerID)
	}
	assertPresenceJSON(t, pubs[1].data, presencev1.EventLeft, joined.ScannerID)
}

func TestHeartbeatPublishesSharedContract(t *testing.T) {
	heartbeatInterval = time.Millisecond
	t.Cleanup(func() { heartbeatInterval = 30 * time.Second })
	if heartbeatv1.SubjectScannerHeartbeatTLS != "scanner.heartbeat.tls" {
		t.Fatalf("subject = %s", heartbeatv1.SubjectScannerHeartbeatTLS)
	}
	if requestv1.SubjectScanRequestedTLS != "scan.requested.tls" || requestv1.SubjectTLSScan != "cafe.discovery.tls.scan" {
		t.Fatalf("requested %s fallback %s", requestv1.SubjectScanRequestedTLS, requestv1.SubjectTLSScan)
	}

	conn := &recordingConn{}
	_, shutdown, err := Runner{}.Start(context.Background(), &core.Deps{NATS: conn})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdown()

	var beat publication
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, pub := range conn.publications() {
			if pub.subject == heartbeatv1.SubjectScannerHeartbeatTLS {
				beat = pub
				break
			}
		}
		if beat.subject != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if beat.subject == "" {
		t.Fatal("heartbeat was not published")
	}
	msg, err := heartbeatv1.Decode(beat.data)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Kind != heartbeatv1.KindTLS || msg.ScannerID == "" || msg.Timestamp == "" {
		t.Fatalf("heartbeat = %#v", msg)
	}
}

func decodePresence(t *testing.T, pub publication) presencev1.Message {
	t.Helper()
	msg, err := presencev1.Decode(pub.data)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func assertPresenceJSON(t *testing.T, raw []byte, event, scannerID string) {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("presence fields = %#v", fields)
	}
	if fields["event"] != event || fields["scanner_id"] != scannerID || fields["type"] != "tls" {
		t.Fatalf("presence = %#v", fields)
	}
	if _, ok := fields["onchain_indexer"]; ok {
		t.Fatalf("presence carried onchain_indexer: %s", raw)
	}
}

type publication struct {
	subject string
	data    []byte
}

type recordingConn struct {
	mu   sync.Mutex
	pubs []publication
}

func (c *recordingConn) Publish(subject string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pubs = append(c.pubs, publication{subject: subject, data: append([]byte(nil), data...)})
	return nil
}

func (c *recordingConn) Subscribe(string, func(*natslib.Msg)) (*natslib.Subscription, error) {
	return nil, nil
}

func (c *recordingConn) ConsumeDurable(context.Context, string, string, func(nats.DurableMessage)) error {
	return nil
}

func (c *recordingConn) Close()            {}
func (c *recordingConn) IsConnected() bool { return true }

func (c *recordingConn) publications() []publication {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]publication, len(c.pubs))
	copy(out, c.pubs)
	return out
}
