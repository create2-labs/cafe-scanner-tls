package core

import (
	"context"

	"cafe-scanner-tls/pkg/nats"
)

// Deps holds shared dependencies for the TLS scanner runner.
// The scanner does not access Postgres; it publishes scan.started/completed/failed to NATS for the persistence-service.
type Deps struct {
	NATS nats.Connection
}

// HealthChecker is implemented by each scanner type for the health endpoint.
type HealthChecker interface {
	IsRunning() bool
}

// Runner starts the TLS scanner and returns health checkers plus a shutdown func.
// The shutdown func must be called on process exit so the scanner can announce "left" via NATS.
type Runner interface {
	// Name returns the scanner kind for health checks and presence ("tls").
	Name() string
	// Start starts the scanner(s). It announces "joined" via NATS before consuming, then returns
	// health checkers and a shutdown func that announces "left" and stops heartbeats.
	Start(ctx context.Context, deps *Deps) ([]HealthChecker, func(), error)
}
