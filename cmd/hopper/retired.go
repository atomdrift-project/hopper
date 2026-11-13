package main

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// retired maps each path hopper no longer serves to the route that replaced
// it, or to "" for a route that went because nothing called it
// (MIGRATION_PLAN.md, "API: one /v1/ surface"). The patterns name no method,
// so a retired path answers 410 whatever a client sends to it.
var retired = map[string]string{
	"/healthz":                  "/_/health",
	"/_/corroboration":          "",
	"/data/":                    "/v1/files/{sha256}",
	"/api/":                     "", // any other old route
	"/api/sample":               "/v1/lookup",
	"/api/sample/{sha256}":      "/v1/lookup",
	"/api/provenance/{sha256}":  "/v1/files/{sha256}/provenance",
	"/api/file/{sha256}":        "/v1/files/{sha256}",
	"/api/locations/incoming":   "/v1/storage/incoming",
	"/api/next":                 "/v1/work/next",
	"/api/heartbeat":            "/v1/work/heartbeat",
	"/api/result":               "/v1/work/result",
	"/api/rescan/{sha256}":      "/v1/work/rescan/{sha256}",
	"/api/release":              "",
	"/api/upload":               "/v1/intake/upload",
	"/api/known":                "/v1/intake/held",
	"/api/popular":              "/v1/intake/popular",
	"/api/sightings":            "/v1/sightings",
	"/api/sightings/ancestry":   "/v1/sightings/ancestry",
	"/api/triage":               "/v1/triage/rulings",
	"/api/triage/queues":        "",
	"/api/triage/{queue}":       "/v1/triage/{queue}",
	"/api/triage/{queue}/depth": "/v1/triage/{queue}/depth",
	"/api/report":               "/v1/triage/reports",
	"/api/stranded/{sha256}":    "",
	"/api/gauntlet/runs":        "",
	"/api/gauntlet/runs/{id}":   "",
}

// registerRetired answers every retired path with 410 Gone.
func registerRetired(mux *http.ServeMux) {
	for pattern, use := range retired {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { serveRetired(w, r, pattern, use) })
	}
}

// serveRetired tells a client still on an old path where the route went, so
// it fails at once, names itself in the log, and does not retry: 410 is
// final. The count covers every request; the log, at most one a minute for
// each route and client, so a polling fleet cannot flood it.
func serveRetired(w http.ResponseWriter, r *http.Request, pattern, use string) {
	ctx := r.Context()
	recordRetired(ctx, pattern)
	agent := r.UserAgent()
	if retiredLog.due(pattern+"\x00"+agent, time.Now()) {
		slog.WarnContext(ctx, "retired API path called",
			"route", pattern, "method", r.Method, "path", r.URL.Path, "use", use,
			"user_agent", agent, "remote", r.RemoteAddr)
	}
	if use == "" {
		v1Error(w, http.StatusGone, "retired", "This path is no longer served.")
		return
	}
	v1Error(w, http.StatusGone, "retired", "This path moved to "+use+".", "use", use)
}

// throttle remembers when each key was last let through.
type throttle struct {
	last  map[string]time.Time
	mu    sync.Mutex
	every time.Duration
}

var retiredLog = &throttle{every: time.Minute, last: map[string]time.Time{}}

// due reports whether key may be logged now, and if so starts its wait.
func (t *throttle) due(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if last, ok := t.last[key]; ok && now.Sub(last) < t.every {
		return false
	}
	// Keys carry a user agent, which the client chooses: forget them all
	// rather than grow without bound.
	if len(t.last) >= 1024 {
		clear(t.last)
	}
	t.last[key] = now
	return true
}

var (
	retiredOnce  sync.Once
	retiredCount metric.Int64Counter
)

// recordRetired counts one request to a retired path, by route. Same
// lazy-create/no-op-on-failure contract as recordLoadShed.
func recordRetired(ctx context.Context, route string) {
	retiredOnce.Do(func() {
		if c, err := otel.Meter(meterName).Int64Counter(
			"hopper.api_retired_requests.total",
			metric.WithDescription("Requests to API paths hopper no longer serves; each names a client still on the old API."),
		); err == nil {
			retiredCount = c
		}
	})
	if retiredCount != nil {
		retiredCount.Add(ctx, 1, metric.WithAttributes(attribute.String("route", route)))
	}
}
