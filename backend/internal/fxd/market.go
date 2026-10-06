package fxd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/fx"
)

// duration is a time.Duration written as a Go duration string ("30s").
type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = duration(v)
	return nil
}

// Market is the static market definition (BILYON_FX_MARKET_FILE): the
// currencies, venues, pair risk, fx books and pricing policy. Ladders and
// mid rates then stream in over NATS.
type Market struct {
	Currencies []struct {
		Code string `json:"code"`
		Exp  int    `json:"exp"`
	} `json:"currencies"`
	Edges []struct {
		ID         string     `json:"id"`
		From       string     `json:"from"`
		To         string     `json:"to"`
		Venue      string     `json:"venue"`
		FeeFixed   int64      `json:"fee_fixed"`
		FeePPM     int64      `json:"fee_ppm"`
		Latency    duration   `json:"latency"`
		StaleAfter duration   `json:"stale_after"`
		Ladder     []fx.Level `json:"ladder"`
		Disabled   bool       `json:"disabled"`
	} `json:"edges"`
	Risk map[string]struct {
		SigmaAnnual float64  `json:"sigma_annual"`
		JumpBps     float64  `json:"jump_bps"`
		MaxTTL      duration `json:"max_ttl"`
	} `json:"risk"`
	FXBooks map[string]uuid.UUID `json:"fx_books"`
	Route   struct {
		MaxHops    int      `json:"max_hops"`
		MaxLatency duration `json:"max_latency"`
		Splits     int      `json:"splits"`
		Chunks     int      `json:"chunks"`
	} `json:"route"`
	Pricing struct {
		Z             float64  `json:"z"`
		MarginBps     float64  `json:"margin_bps"`
		MaxAdverseBps float64  `json:"max_adverse_bps"`
		Overbook      float64  `json:"overbook"`
		DefaultTTL    duration `json:"default_ttl"`
		MinTTL        duration `json:"min_ttl"`
		MidStaleAfter duration `json:"mid_stale_after"`
		SnipingRatio  float64  `json:"sniping_ratio"`
		SnipingWindow duration `json:"sniping_window"`
	} `json:"pricing"`
}

func decodeStrict(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// LoadMarket reads a market file; unknown fields are errors.
func LoadMarket(path string) (*Market, error) {
	var m Market
	if err := decodeStrict(path, &m); err != nil {
		return nil, err
	}
	if len(m.Currencies) < 2 || len(m.Edges) == 0 || len(m.Risk) == 0 || len(m.FXBooks) == 0 {
		return nil, fmt.Errorf("%s: currencies, edges, risk and fx_books are required", path)
	}
	return &m, nil
}

// Graph builds the liquidity graph.
func (m *Market) Graph(cfg fx.GraphConfig) (*fx.Graph, error) {
	cs := make([]fx.Currency, len(m.Currencies))
	for i, c := range m.Currencies {
		cs[i] = fx.Currency{Code: c.Code, Exp: c.Exp}
	}
	g, err := fx.NewGraph(cfg, cs...)
	if err != nil {
		return nil, err
	}
	for _, e := range m.Edges {
		spec := fx.EdgeSpec{ID: e.ID, From: e.From, To: e.To, Venue: e.Venue, FeeFixed: e.FeeFixed, FeePPM: e.FeePPM,
			Latency: time.Duration(e.Latency), StaleAfter: time.Duration(e.StaleAfter)}
		if err := g.AddEdge(spec, e.Ladder); err != nil {
			return nil, err
		}
		if e.Disabled {
			if err := g.SetEnabled(e.ID, false); err != nil {
				return nil, err
			}
		}
	}
	return g, nil
}

// EngineConfig is the engine configuration the market defines.
func (m *Market) EngineConfig(keys []fx.QuoteKey) fx.Config {
	risk := make(map[string]fx.PairRisk, len(m.Risk))
	for pair, r := range m.Risk {
		risk[pair] = fx.PairRisk{SigmaAnnual: r.SigmaAnnual, JumpBps: r.JumpBps, MaxTTL: time.Duration(r.MaxTTL)}
	}
	p := m.Pricing
	return fx.Config{
		Route: fx.RouteOptions{MaxHops: m.Route.MaxHops, MaxLatency: time.Duration(m.Route.MaxLatency),
			Splits: m.Route.Splits, Chunks: m.Route.Chunks},
		Z: p.Z, MarginBps: p.MarginBps, MaxAdverseBps: p.MaxAdverseBps, Overbook: p.Overbook,
		DefaultTTL: time.Duration(p.DefaultTTL), MinTTL: time.Duration(p.MinTTL), MidStaleAfter: time.Duration(p.MidStaleAfter),
		SnipingRatio: p.SnipingRatio, SnipingWindow: time.Duration(p.SnipingWindow),
		Risk: risk, Keys: keys, FXBooks: m.FXBooks,
	}
}

// LoadQuoteKeys reads K_quote generations (BILYON_FX_QUOTE_KEYS_FILE), a
// JSON array of {"id": ..., "secret": base64}; the first signs.
func LoadQuoteKeys(path string) ([]fx.QuoteKey, error) {
	var raw []struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := decodeStrict(path, &raw); err != nil {
		return nil, err
	}
	keys := make([]fx.QuoteKey, 0, len(raw))
	for _, k := range raw {
		secret, err := base64.StdEncoding.DecodeString(k.Secret)
		if err != nil {
			return nil, fmt.Errorf("%s: key %q: %w", path, k.ID, err)
		}
		keys = append(keys, fx.QuoteKey{ID: k.ID, Secret: secret})
	}
	return keys, nil
}
