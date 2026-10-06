// Package config reads typed settings from the environment. Every problem is
// collected so a misconfigured service fails at startup with one complete
// message instead of one error per restart.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env is a typed view over environment variables.
type Env struct {
	lookup func(string) (string, bool)
	errs   []error
}

// FromOS reads the process environment.
func FromOS() *Env { return &Env{lookup: os.LookupEnv} }

// FromMap reads a fixed map (tests, embedded use).
func FromMap(m map[string]string) *Env {
	return &Env{lookup: func(k string) (string, bool) { v, ok := m[k]; return v, ok }}
}

func (e *Env) get(name string) (string, bool) {
	v, ok := e.lookup(name)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

func (e *Env) fail(name, format string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...)))
}

// String returns the variable or def.
func (e *Env) String(name, def string) string {
	if v, ok := e.get(name); ok {
		return v
	}
	return def
}

// Required returns the variable or records an error.
func (e *Env) Required(name string) string {
	v, ok := e.get(name)
	if !ok {
		e.fail(name, "is required")
	}
	return v
}

// OneOf returns the variable (or def) and records an error unless it is allowed.
func (e *Env) OneOf(name, def string, allowed ...string) string {
	v := e.String(name, def)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	e.fail(name, "must be one of %s, got %q", strings.Join(allowed, ", "), v)
	return def
}

// Int returns the variable as an int within [min, max], or def.
func (e *Env) Int(name string, def, min, max int) int {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		e.fail(name, "must be an integer in [%d, %d], got %q", min, max, v)
		return def
	}
	return n
}

// Duration returns the variable as a positive Go duration ("1s", "15m"), or def.
func (e *Env) Duration(name string, def time.Duration) time.Duration {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		e.fail(name, "must be a positive duration such as 30s or 15m, got %q", v)
		return def
	}
	return d
}

// Bool returns the variable as a boolean, or def.
func (e *Env) Bool(name string, def bool) bool {
	v, ok := e.get(name)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.fail(name, "must be a boolean, got %q", v)
		return def
	}
	return b
}

// Err returns every recorded problem, or nil.
func (e *Env) Err() error { return errors.Join(e.errs...) }
