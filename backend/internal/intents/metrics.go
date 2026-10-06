package intents

import "github.com/prometheus/client_golang/prometheus"

type metrics struct {
	transitions *prometheus.CounterVec // by target state and reason
	ledger      *prometheus.CounterVec // transient ledger/FX failures by operation
	swept       *prometheus.CounterVec // sweeper work by kind
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		transitions: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "bilyon", Subsystem: "intents",
			Name: "transitions_total", Help: "Intent state transitions by target state and reason."},
			[]string{"state", "reason"}),
		ledger: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "bilyon", Subsystem: "intents",
			Name: "dependency_failures_total", Help: "Transient ledger and FX failures by operation; retried."},
			[]string{"op"}),
		swept: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "bilyon", Subsystem: "intents",
			Name: "swept_total", Help: "Intents moved by the sweeper by kind."}, []string{"kind"}),
	}
	if reg != nil {
		reg.MustRegister(m.transitions, m.ledger, m.swept)
	}
	return m
}

func (m *metrics) moved(in *Intent) {
	if in != nil {
		m.transitions.WithLabelValues(string(in.State), in.Reason).Inc()
	}
}
