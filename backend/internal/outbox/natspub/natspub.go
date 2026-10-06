// Package natspub publishes outbox messages to NATS JetStream.
//
// Each message is published to "<prefix>.<topic>" with Nats-Msg-Id set to the
// outbox row id, so JetStream drops redeliveries of the same row inside the
// stream's duplicate window. Publish returns only after the JetStream PubAck,
// i.e. once the message is durably stored.
package natspub

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
)

// Header names set on every published message.
const (
	HeaderOutboxID  = "Bilyon-Outbox-Id"
	HeaderKey       = "Bilyon-Key"
	HeaderPartition = "Bilyon-Partition"
)

// StreamConfig describes the JetStream stream that stores a service's events.
type StreamConfig struct {
	Name            string        // default "BILYON_LEDGER"
	SubjectPrefix   string        // default "bilyon"; messages go to "<prefix>.<topic>"
	Subjects        []string      // stream subjects, default ["<prefix>.ledger.>"]
	MaxAge          time.Duration // default 7 days
	DuplicateWindow time.Duration // default 2 minutes
	Replicas        int           // default 1 (3 in production clusters)
	EnsureOnConnect bool          // create or update the stream at startup
}

func (c *StreamConfig) normalise() {
	if c.Name == "" {
		c.Name = "BILYON_LEDGER"
	}
	if c.SubjectPrefix == "" {
		c.SubjectPrefix = "bilyon"
	}
	if len(c.Subjects) == 0 {
		c.Subjects = []string{c.SubjectPrefix + ".ledger.>"}
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 7 * 24 * time.Hour
	}
	if c.DuplicateWindow <= 0 {
		c.DuplicateWindow = 2 * time.Minute
	}
	if c.Replicas <= 0 {
		c.Replicas = 1
	}
}

// Publisher implements outbox.Publisher.
type Publisher struct {
	js     jetstream.JetStream
	prefix string
}

var _ outbox.Publisher = (*Publisher)(nil)

// New wraps a NATS connection and, when cfg.EnsureOnConnect is set, creates
// or updates the stream.
func New(ctx context.Context, nc *nats.Conn, cfg StreamConfig) (*Publisher, error) {
	cfg.normalise()
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("natspub: jetstream: %w", err)
	}
	if cfg.EnsureOnConnect {
		if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
			Name:       cfg.Name,
			Subjects:   cfg.Subjects,
			Storage:    jetstream.FileStorage,
			Retention:  jetstream.LimitsPolicy,
			MaxAge:     cfg.MaxAge,
			Duplicates: cfg.DuplicateWindow,
			Replicas:   cfg.Replicas,
			Discard:    jetstream.DiscardOld,
		}); err != nil {
			return nil, fmt.Errorf("natspub: ensure stream %s: %w", cfg.Name, err)
		}
	}
	return &Publisher{js: js, prefix: cfg.SubjectPrefix}, nil
}

// Subject returns the subject a topic is published on.
func (p *Publisher) Subject(topic string) string { return p.prefix + "." + topic }

// Publish implements outbox.Publisher.
func (p *Publisher) Publish(ctx context.Context, m outbox.Message) error {
	msg := nats.NewMsg(p.Subject(m.Topic))
	msg.Data = m.Payload
	for k, v := range m.Headers {
		msg.Header.Set(k, v)
	}
	id := strconv.FormatInt(m.ID, 10)
	msg.Header.Set(jetstream.MsgIDHeader, "outbox-"+id)
	msg.Header.Set(HeaderOutboxID, id)
	msg.Header.Set(HeaderKey, m.Key)
	msg.Header.Set(HeaderPartition, strconv.Itoa(int(m.Partition)))
	msg.Header.Set("Content-Type", "application/cloudevents+json")
	ack, err := p.js.PublishMsg(ctx, msg)
	if err != nil {
		return fmt.Errorf("natspub: publish %s #%d: %w", m.Topic, m.ID, err)
	}
	if ack == nil {
		return errors.New("natspub: nil ack")
	}
	return nil
}
