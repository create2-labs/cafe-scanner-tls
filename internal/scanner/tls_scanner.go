package scanner

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"cafe-scanner-tls/pkg/nats"
	"cafe-scanner-tls/pkg/scan"

	lifecyclev1 "github.com/create2-labs/cafe-contracts/discovery/scanlifecycle/v1"
	requestv1 "github.com/create2-labs/cafe-contracts/discovery/scanrequest/v1"
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
		scanMsg, err := requestv1.DecodeTLS(data)
		if err != nil {
			log.Printf("Failed to unmarshal TLS scan message: %v", err)
			return nil
		}
		if scanMsg.ScanID == requestv1.NilID {
			scanMsg.ScanID = uuid.New().String()
		}
		log.Printf("[NATS] RECV scan_id=%s endpoint=%s component=scanner-tls", scanMsg.ScanID, scanMsg.Endpoint)
		started := lifecyclev1.Started{
			ScanID: scanMsg.ScanID, Kind: scan.KindTLS, UserID: scanMsg.UserID,
			StartedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: scanMsg.Endpoint,
		}
		log.Printf("[NATS] PUB subject=scan.started scan_id=%s component=scanner-tls", scanMsg.ScanID)
		if err := nats.PublishJSON(w.base.natsConn, lifecyclev1.SubjectScanStarted, started); err != nil {
			log.Printf("Failed to publish scan.started: %v", err)
		}
		target, err := w.plugin.DecodeMessage(&scanMsg)
		if err != nil {
			log.Printf("Error decoding tls scan message: %v", err)
			return w.failOrRetry(last, scanMsg, err)
		}
		result, err := w.plugin.Run(context.Background(), scanUserID(scanMsg.UserID), target, scan.RunOptions{IsDefault: scanMsg.IsDefault, SkipPersist: true})
		if err != nil {
			return w.failOrRetry(last, scanMsg, err)
		}
		resultRaw, err := lifecycleResult(result)
		if err != nil {
			return w.failOrRetry(last, scanMsg, err)
		}
		completed := lifecyclev1.Completed{
			ScanID: scanMsg.ScanID, Kind: scan.KindTLS, UserID: scanMsg.UserID,
			CompletedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: scanMsg.Endpoint,
			Result: resultRaw,
		}
		log.Printf("[NATS] PUB subject=scan.completed scan_id=%s component=scanner-tls", scanMsg.ScanID)
		if err := nats.PublishJSON(w.base.natsConn, lifecyclev1.SubjectScanCompleted, completed); err != nil {
			log.Printf("Failed to publish scan.completed: %v", err)
			return w.failOrRetry(last, scanMsg, err)
		}
		return nil
	})
}

func scanUserID(id string) *uuid.UUID {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil {
		return nil
	}
	return &parsed
}

func lifecycleResult(result scan.ScanResult) (json.RawMessage, error) {
	if result == nil {
		return nil, nil
	}
	var payload any = result
	if raw, ok := result.(scan.RawResult); ok {
		payload = raw.Raw()
	}
	if payload == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil || string(encoded) == "null" {
		return nil, err
	}
	return encoded, nil
}

func (w *TLSScanner) failOrRetry(last bool, scanMsg requestv1.TLS, cause error) error {
	if !last {
		return cause
	}
	if err := publishTLSScanFailed(w.base.natsConn, scanMsg.ScanID, scanMsg.UserID, scanMsg.Endpoint, cause.Error()); err != nil {
		return err
	}
	return nil
}

func publishTLSScanFailed(conn nats.Connection, scanID, userID, endpoint, errMsg string) error {
	log.Printf("[NATS] PUB subject=scan.failed scan_id=%s component=scanner-tls error=%s", scanID, errMsg)
	return nats.PublishJSON(conn, lifecyclev1.SubjectScanFailed, lifecyclev1.Failed{
		ScanID: scanID, Kind: scan.KindTLS, UserID: userID,
		Error: errMsg, CompletedAt: time.Now().UTC().Format(time.RFC3339), Endpoint: endpoint,
	})
}
