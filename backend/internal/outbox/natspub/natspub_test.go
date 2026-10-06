package natspub_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/bil1234n/bilyon/backend/internal/outbox"
	"github.com/bil1234n/bilyon/backend/internal/outbox/natspub"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/ledgerdb"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/natstest"
	"github.com/bil1234n/bilyon/backend/internal/testinfra/pgtest"
)

var srv *pgtest.Server

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m, ledgerdb.Setup, &srv)) }

func bg(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestRelayToJetStreamEndToEnd(t *testing.T) {
	pool := srv.Database(t)
	ns := natstest.Start(t)
	nc := ns.Connect(t)
	pub, err := natspub.New(bg(t), nc, natspub.StreamConfig{EnsureOnConnect: true, DuplicateWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		if err := pgx.BeginFunc(bg(t), pool, func(tx pgx.Tx) error {
			_, err := outbox.Write(bg(t), tx, outbox.Event{Topic: "ledger.entry.posted", Key: fmt.Sprintf("intent:%d", i%3),
				Subject: fmt.Sprintf("entry-%d", i), Data: map[string]int{"n": i}, Headers: map[string]string{"Trace-Id": "abc"}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	relay := outbox.NewRelay(pool, pub, outbox.RelayConfig{PollInterval: 20 * time.Millisecond})
	go func() { _ = relay.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	js, _ := jetstream.New(nc)
	stream, err := js.Stream(bg(t), "BILYON_LEDGER")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		info, err := stream.Info(bg(t))
		if err != nil {
			t.Fatal(err)
		}
		if info.State.Msgs == 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream has %d messages, want 10", info.State.Msgs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cons, err := stream.CreateOrUpdateConsumer(bg(t), jetstream.ConsumerConfig{AckPolicy: jetstream.AckExplicitPolicy})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := cons.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lastByKey := map[string]int{}
	n := 0
	for msg := range batch.Messages() {
		n++
		h := msg.Headers()
		if msg.Subject() != "bilyon.ledger.entry.posted" || h.Get("Content-Type") != "application/cloudevents+json" ||
			h.Get("Trace-Id") != "abc" || h.Get(natspub.HeaderOutboxID) == "" || h.Get(jetstream.MsgIDHeader) == "" {
			t.Fatalf("message metadata: subject=%s headers=%v", msg.Subject(), h)
		}
		var env outbox.Envelope
		if err := json.Unmarshal(msg.Data(), &env); err != nil || env.Type != "ledger.entry.posted" || env.SpecVersion != "1.0" {
			t.Fatalf("payload: %s (%v)", msg.Data(), err)
		}
		var data map[string]int
		_ = json.Unmarshal(env.Data, &data)
		key := h.Get(natspub.HeaderKey)
		if prev, ok := lastByKey[key]; ok && data["n"] <= prev {
			t.Fatalf("key %s delivered out of order", key)
		}
		lastByKey[key] = data["n"]
		_ = msg.Ack()
	}
	if n != 10 {
		t.Fatalf("consumed %d messages", n)
	}
}

func TestRepublishedRowIsDeduplicatedByJetStream(t *testing.T) {
	ns := natstest.Start(t)
	nc := ns.Connect(t)
	pub, err := natspub.New(bg(t), nc, natspub.StreamConfig{EnsureOnConnect: true, Name: "DEDUP", SubjectPrefix: "dedup"})
	if err != nil {
		t.Fatal(err)
	}
	m := outbox.Message{ID: 42, Topic: "ledger.hold.placed", Key: "intent:1", Payload: []byte(`{"x":1}`)}
	for range 3 { // the relay crashed after publishing but before marking the row
		if err := pub.Publish(bg(t), m); err != nil {
			t.Fatal(err)
		}
	}
	js, _ := jetstream.New(nc)
	stream, _ := js.Stream(bg(t), "DEDUP")
	info, err := stream.Info(bg(t))
	if err != nil || info.State.Msgs != 1 {
		t.Fatalf("stream holds %d copies (%v)", info.State.Msgs, err)
	}
}

func TestPublishFailsWithoutStream(t *testing.T) {
	ns := natstest.Start(t)
	nc := ns.Connect(t)
	pub, err := natspub.New(bg(t), nc, natspub.StreamConfig{SubjectPrefix: "nostream"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pub.Publish(ctx, outbox.Message{ID: 1, Topic: "ledger.x", Key: "k", Payload: []byte("{}")}); err == nil {
		t.Fatal("publish without a stream must fail so the relay retries")
	}
}
