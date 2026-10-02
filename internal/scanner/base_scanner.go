package scanner

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"cafe-scanner-tls/pkg/nats"

	"github.com/google/uuid"
)

const inProgressEvery = 30 * time.Second

// DeliveryHandler processes one scan request.
// last is true when this is the final delivery JetStream will make.
// A nil error means the delivery is finished: the handler published scan.completed,
// or scan.failed on the last delivery, or the payload cannot be read.
type DeliveryHandler func(data []byte, last bool) error

// BaseScanner provides common functionality for all scanners
type BaseScanner struct {
	natsConn  nats.Connection
	subject   string
	durable   string
	handler   DeliveryHandler
	name      string
	isRunning bool
	gate      *workGate
	mu        sync.Mutex
}

// NewBaseScanner creates a new base scanner
func NewBaseScanner(natsConn nats.Connection, subject, durable, name string, handler DeliveryHandler) *BaseScanner {
	return &BaseScanner{
		natsConn: natsConn,
		subject:  subject,
		durable:  durable,
		handler:  handler,
		name:     name,
		gate:     newWorkGate(),
	}
}

// Start binds the durable work-queue consumer. It retries until the stream exists.
func (w *BaseScanner) Start(ctx context.Context) error {
	go w.bind(ctx)
	return nil
}

func (w *BaseScanner) bind(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := w.natsConn.ConsumeDurable(ctx, w.subject, w.durable, w.onMessage)
		if err == nil {
			w.mu.Lock()
			w.isRunning = true
			w.mu.Unlock()
			log.Printf("%s scanner started and subscribed to %s", w.name, w.subject)
			return
		}
		log.Printf("%s scanner waiting for %s: %v", w.name, w.subject, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// IsRunning returns whether the scanner is currently running
func (w *BaseScanner) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.isRunning
}

// GetName returns the scanner name
func (w *BaseScanner) GetName() string {
	return w.name
}

func (w *BaseScanner) onMessage(msg nats.DurableMessage) {
	var probe struct {
		ScanID uuid.UUID `json:"scan_id"`
	}
	_ = json.Unmarshal(msg.Data(), &probe)
	key := deliveryKey(probe.ScanID.String(), msg.Sequence())
	if probe.ScanID == uuid.Nil {
		key = deliveryKey("", msg.Sequence())
	}

	w.mu.Lock()
	decision := w.gate.Begin(key)
	w.mu.Unlock()

	switch decision {
	case decisionAck:
		if err := msg.Ack(); err != nil {
			log.Printf("%s scanner ack of finished %s: %v", w.name, key, err)
		}
		return
	case decisionBusy:
		if err := msg.InProgress(); err != nil {
			log.Printf("%s scanner in-progress for %s: %v", w.name, key, err)
		}
		return
	}

	go w.runDelivery(msg, key)
}

func (w *BaseScanner) runDelivery(msg nats.DurableMessage, key string) {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(inProgressEvery)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				_ = msg.InProgress()
			}
		}
	}()

	last := msg.NumDelivered() >= uint64(nats.ScanRequestMaxDeliver)
	err := w.handler(msg.Data(), last)
	close(done)

	w.mu.Lock()
	w.gate.Finish(key, err == nil)
	w.mu.Unlock()

	if err != nil {
		log.Printf("Error processing message in %s scanner: %v", w.name, err)
		if nakErr := msg.Nak(); nakErr != nil {
			log.Printf("%s scanner nak %s: %v", w.name, key, nakErr)
		}
		return
	}
	if ackErr := msg.Ack(); ackErr != nil {
		log.Printf("%s scanner ack %s: %v", w.name, key, ackErr)
	}
}

// UnmarshalMessage decodes a scan request payload.
func UnmarshalMessage(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
