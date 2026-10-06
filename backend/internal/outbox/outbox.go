// Package outbox implements the transactional outbox (RFC 0001 §2.3.1 I6).
//
// Producers call Write inside the same database transaction as the state
// change they announce, so an event exists if and only if the change
// committed. A Relay later publishes pending rows in order and marks them.
//
// Ordering: rows are partitioned by a stable hash of their key (16
// partitions). Exactly one relay owns a partition at a time (advisory lock),
// publishes in id order, and never publishes a message while an older
// message with the same key is still pending.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Partitions is the fixed number of outbox partitions (see the schema CHECK).
const Partitions = 16

// Source identifies events produced by this service in CloudEvents "source".
const Source = "bilyon.ledger"

// Partition maps a message key to its partition. The hash is computed in Go
// (FNV-1a) rather than in SQL so it can never change under a database upgrade.
func Partition(key string) int16 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return int16(h.Sum32() % Partitions)
}

// Envelope is the CloudEvents 1.0 structured-mode JSON envelope stored as the
// row payload and published verbatim.
type Envelope struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"`
	Subject         string          `json:"subject,omitempty"`
	Time            time.Time       `json:"time"`
	DataContentType string          `json:"datacontenttype"`
	Data            json.RawMessage `json:"data"`
}

// Event is what producers write.
type Event struct {
	Topic   string            // e.g. "ledger.entry.posted"
	Key     string            // ordering key, e.g. "intent:<id>" or an entry id
	Subject string            // CloudEvents subject (optional)
	Data    any               // JSON-serialisable payload
	Headers map[string]string // transport headers (optional)
}

// Write inserts an event in the caller's transaction and returns its envelope.
func Write(ctx context.Context, tx pgx.Tx, ev Event) (Envelope, error) {
	if ev.Topic == "" || ev.Key == "" {
		return Envelope{}, fmt.Errorf("outbox: topic and key are required")
	}
	data, err := json.Marshal(ev.Data)
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: encode %s payload: %w", ev.Topic, err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: event id: %w", err)
	}
	env := Envelope{
		SpecVersion:     "1.0",
		ID:              id.String(),
		Source:          Source,
		Type:            ev.Topic,
		Subject:         ev.Subject,
		Time:            time.Now().UTC().Round(time.Microsecond),
		DataContentType: "application/json",
		Data:            data,
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return Envelope{}, fmt.Errorf("outbox: encode envelope: %w", err)
	}
	headers := ev.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	// The subquery (an optimisation fence) assigns the transaction id before
	// the identity default draws the row id: a transaction holding an outbox
	// id is then always in flight in concurrent snapshots, which table
	// tailers rely on to resolve gaps (migration 0002).
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (topic, msg_key, partition, payload, headers, txid)
		SELECT v.topic, v.msg_key, v.partition, v.payload, v.headers, v.txid
		  FROM (SELECT $1::text AS topic, $2::text AS msg_key, $3::smallint AS partition, $4::jsonb AS payload,
		               $5::jsonb AS headers, pg_current_xact_id() AS txid OFFSET 0) v`,
		ev.Topic, ev.Key, Partition(ev.Key), payload, headers); err != nil {
		return Envelope{}, fmt.Errorf("outbox: insert %s: %w", ev.Topic, err)
	}
	return env, nil
}
