package tlsrunner

import (
	"context"
	"log"
	"time"

	"cafe-scanner-tls/internal/config"
	"cafe-scanner-tls/internal/scan/tls"
	scanner "cafe-scanner-tls/internal/scanner"
	"cafe-scanner-tls/internal/scanner/core"
	"cafe-scanner-tls/internal/tlsscan"
	"cafe-scanner-tls/pkg/nats"
	"cafe-scanner-tls/pkg/scan"

	heartbeatv1 "github.com/create2-labs/cafe-contracts/discovery/scannerheartbeat/v1"
	presencev1 "github.com/create2-labs/cafe-contracts/discovery/scannerpresence/v1"
	requestv1 "github.com/create2-labs/cafe-contracts/discovery/scanrequest/v1"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

var heartbeatInterval = 30 * time.Second

// Runner starts the TLS scan scanner (consumes NATS TLS subject).
type Runner struct{}

// Name implements core.Runner.
func (Runner) Name() string { return "tls" }

// Start implements core.Runner: announces joined via NATS, starts heartbeat, wires plugin and scanner, returns health checkers and shutdown func.
func (Runner) Start(ctx context.Context, deps *core.Deps) ([]core.HealthChecker, func(), error) {
	scannerID := uuid.New().String()
	presence := presencev1.Message{
		Event:     presencev1.EventJoined,
		ScannerID: scannerID,
		Type:      "tls",
	}
	if err := nats.PublishJSON(deps.NATS, presencev1.Subject, presence); err != nil {
		return nil, nil, err
	}
	log.Printf("TLS scanner %s announced joined", scannerID)

	// Heartbeat republishes this same presence value.
	heartbeatCtx, stopHeartbeat := context.WithCancel(context.Background())
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				_ = nats.PublishJSON(deps.NATS, presencev1.Subject, presence)
				_ = nats.PublishJSON(deps.NATS, heartbeatv1.SubjectScannerHeartbeatTLS, heartbeatv1.Message{
					ScannerID: scannerID, Kind: heartbeatv1.KindTLS, Timestamp: time.Now().UTC().Format(time.RFC3339),
				})
			}
		}
	}()

	engine := tlsscan.NewTLSScanEngine()
	tlsPlugin := tls.NewPlugin(engine, viper.GetString(config.ScanPluginsTLSVersion), requestv1.SubjectScanRequestedTLS)
	scan.Register(tlsPlugin)

	w := scanner.NewTLSScanner(scan.Get(scan.KindTLS), deps.NATS)
	if err := w.Start(ctx); err != nil {
		stopHeartbeat()
		return nil, nil, err
	}

	shutdown := func() {
		stopHeartbeat()
		left := presencev1.Message{Event: presencev1.EventLeft, ScannerID: scannerID, Type: "tls"}
		_ = nats.PublishJSON(deps.NATS, presencev1.Subject, left)
		log.Printf("TLS scanner %s announced left", scannerID)
	}
	return []core.HealthChecker{w}, shutdown, nil
}
