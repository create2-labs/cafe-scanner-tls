package nats

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog/log"
)

const (
	// StreamScanRequested is the work-queue stream declared by cafe-deploy and cafe-expresso.
	StreamScanRequested = "SCAN_REQUESTED"
	// DurableScannerTLS is the single durable consumer for scan.requested.tls.
	// Replicas of this scanner share it, so each message is delivered once at a time.
	DurableScannerTLS = "scanner-tls"
	// ScanRequestMaxDeliver is the last delivery. The scanner then publishes scan.failed and acks.
	ScanRequestMaxDeliver = 5
	// ScanRequestAckWait is how long JetStream waits for an ack before redelivering.
	ScanRequestAckWait = 2 * time.Minute
)

// DurableMessage is one delivery of a scan request held by the work queue.
type DurableMessage interface {
	Data() []byte
	NumDelivered() uint64
	Sequence() uint64
	Ack() error
	Nak() error
	InProgress() error
}

type jsMessage struct {
	msg jetstream.Msg
}

func (m jsMessage) Data() []byte { return m.msg.Data() }

func (m jsMessage) NumDelivered() uint64 {
	meta, err := m.msg.Metadata()
	if err != nil || meta == nil {
		return 1
	}
	return meta.NumDelivered
}

func (m jsMessage) Sequence() uint64 {
	meta, err := m.msg.Metadata()
	if err != nil || meta == nil {
		return 0
	}
	return meta.Sequence.Stream
}

func (m jsMessage) Ack() error        { return m.msg.Ack() }
func (m jsMessage) Nak() error        { return m.msg.Nak() }
func (m jsMessage) InProgress() error { return m.msg.InProgress() }

// ConsumeDurable binds the work-queue consumer for subject and returns once it is delivering.
// The consumer stays alive until ctx is cancelled.
func (nc *natsConnection) ConsumeDurable(ctx context.Context, subject, durable string, handler func(DurableMessage)) error {
	if nc.conn == nil {
		return errors.New("nats connection is nil")
	}
	js, err := jetstream.New(nc.conn)
	if err != nil {
		return fmt.Errorf("jetstream: %w", err)
	}
	stream, err := js.Stream(ctx, StreamScanRequested)
	if err != nil {
		return fmt.Errorf("stream %s: %w", StreamScanRequested, err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       durable,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ScanRequestAckWait,
		MaxDeliver:    ScanRequestMaxDeliver,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: 64,
	})
	if err != nil {
		return fmt.Errorf("consumer %s: %w", durable, err)
	}
	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		handler(jsMessage{msg: msg})
	}, jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
		log.Error().Err(err).Str("durable", durable).Str("subject", subject).Msg("scan request consumer error")
	}))
	if err != nil {
		return fmt.Errorf("consume %s: %w", durable, err)
	}
	go func() {
		<-ctx.Done()
		cc.Stop()
	}()
	return nil
}
