package scanner

import (
	"context"
	"log"
	"time"

	"cafe-scanner-tls/pkg/nats"
	"cafe-scanner-tls/pkg/scan"

	"github.com/google/uuid"
)

// maxConcurrentTLSScans limits how many TLS scans run at once (each does network I/O + optional OpenSSL).
const maxConcurrentTLSScans = 5

// TLSScanner processes TLS scan messages from NATS via the TLS plugin.
type TLSScanner struct {
	plugin scan.Plugin
	base   *BaseScanner
	sem    chan struct{}
}

// NewTLSScanner creates a new TLS scanner.
func NewTLSScanner(plugin scan.Plugin, natsConn nats.Connection) *TLSScanner {
	w := &TLSScanner{
		plugin: plugin,
		sem:    make(chan struct{}, maxConcurrentTLSScans),
	}
	d := plugin.Descriptor()
	w.base = NewBaseScanner(natsConn, d.Subject, nats.DurableScannerTLS, "TLS", w.handleDelivery)
	return w
}

// Start starts the scanner and subscribes to NATS messages.
func (w *TLSScanner) Start(ctx context.Context) error {
	return w.base.Start(ctx)
}

// IsRunning returns whether the scanner is currently running.
func (w *TLSScanner) IsRunning() bool {
	return w.base.IsRunning()
}

func (w *TLSScanner) handleDelivery(data []byte, last bool) error {
	return ProcessWithConcurrency("TLS", scan.KindTLS, w.plugin.Descriptor().Subject, w.sem, nil, func() error {
		var scanMsg nats.TLSScanMessage
		if err := UnmarshalMessage(data, &scanMsg); err != nil {
			log.Printf("Failed to unmarshal TLS scan message: %v", err)
			return nil
		}
		if scanMsg.ScanID == uuid.Nil {
			scanMsg.ScanID = uuid.New()
		}
		log.Printf("[NATS] RECV scan_id=%s endpoint=%s component=scanner-tls", scanMsg.ScanID.String(), scanMsg.Endpoint)
		started := nats.ScanStartedMessage{
			ScanID: scanMsg.ScanID, Kind: "tls", UserID: scanMsg.UserID,
			StartedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: scanMsg.Endpoint,
		}
		log.Printf("[NATS] PUB subject=scan.started scan_id=%s component=scanner-tls", scanMsg.ScanID.String())
		if err := nats.PublishJSON(w.base.natsConn, nats.SubjectScanStarted, started); err != nil {
			log.Printf("Failed to publish scan.started: %v", err)
		}
		target, err := w.plugin.DecodeMessage(&scanMsg)
		if err != nil {
			log.Printf("Error decoding tls scan message: %v", err)
			return w.failOrRetry(last, scanMsg, err)
		}
		userID := &scanMsg.UserID
		if scanMsg.UserID == uuid.Nil {
			userID = nil
		}
		result, err := w.plugin.Run(context.Background(), userID, target, scan.RunOptions{IsDefault: scanMsg.IsDefault, SkipPersist: true})
		if err != nil {
			return w.failOrRetry(last, scanMsg, err)
		}
		var resultPayload interface{} = result
		if r, ok := result.(scan.RawResult); ok {
			resultPayload = r.Raw()
		}
		completed := nats.ScanCompletedMessage{
			ScanID: scanMsg.ScanID, Kind: "tls", UserID: scanMsg.UserID,
			CompletedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: scanMsg.Endpoint,
			Result: resultPayload,
		}
		log.Printf("[NATS] PUB subject=scan.completed scan_id=%s component=scanner-tls", scanMsg.ScanID.String())
		if err := nats.PublishJSON(w.base.natsConn, nats.SubjectScanCompleted, completed); err != nil {
			log.Printf("Failed to publish scan.completed: %v", err)
			return w.failOrRetry(last, scanMsg, err)
		}
		return nil
	})
}

func (w *TLSScanner) failOrRetry(last bool, scanMsg nats.TLSScanMessage, cause error) error {
	if !last {
		return cause
	}
	if err := publishTLSScanFailed(w.base.natsConn, scanMsg.ScanID, scanMsg.UserID, scanMsg.Endpoint, cause.Error()); err != nil {
		return err
	}
	return nil
}

func publishTLSScanFailed(conn nats.Connection, scanID, userID uuid.UUID, endpoint, errMsg string) error {
	log.Printf("[NATS] PUB subject=scan.failed scan_id=%s component=scanner-tls error=%s", scanID.String(), errMsg)
	return nats.PublishJSON(conn, nats.SubjectScanFailed, nats.ScanFailedMessage{
		ScanID: scanID, Kind: "tls", UserID: userID,
		Error: errMsg, CompletedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: endpoint,
	})
}
