package main

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

// genericAgents are the user agents HTTP libraries and tools send when their
// caller names nothing, matched case-insensitively on the product token (what
// precedes the first "/" or space). A request carrying one could be any
// program at all; hopper wants to know which of its clients is calling.
var genericAgents = map[string]bool{
	"go-http-client":    true,
	"curl":              true,
	"wget":              true,
	"python-requests":   true,
	"python-urllib":     true,
	"python-httpx":      true,
	"aiohttp":           true,
	"reqwest":           true,
	"hyper":             true,
	"okhttp":            true,
	"java":              true,
	"apache-httpclient": true,
	"node-fetch":        true,
	"node":              true,
	"undici":            true,
	"axios":             true,
	"got":               true,
	"libwww-perl":       true,
	"ruby":              true,
	"faraday":           true,
}

// clientAgent is the user agent hopper sends when it calls a hopper API:
// hopper/ and the revision it was built from.
var clientAgent = "hopper/" + buildRevision()

// buildRevision is the VCS revision this binary was built from, shortened, or
// "dev" for a build that recorded none.
func buildRevision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value[:min(len(s.Value), 12)]
			}
		}
	}
	return "dev"
}

// agentLog throttles the rejection log: once a minute for each path, agent
// and caller.
var agentLog = &throttle{every: time.Minute, last: map[string]time.Time{}}

// namedAgent reports whether agent names a client: not empty, and not a
// library's default.
func namedAgent(agent string) bool {
	agent = strings.TrimSpace(agent)
	product, _, _ := strings.Cut(agent, "/")
	product, _, _ = strings.Cut(product, " ")
	return product != "" && !genericAgents[strings.ToLower(product)]
}

// agentMiddleware refuses API requests whose User-Agent does not name the
// client that sent them (namedAgent), so every caller in a log or a metric can
// be told apart and found. The probes (authExemptPaths) are left to monitors,
// and a retired path still answers 410 with the route that replaced it, which
// a client that has not been updated needs more than this refusal.
func agentMiddleware(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := r.UserAgent()
		if namedAgent(agent) || authExemptPaths[r.URL.Path] {
			mux.ServeHTTP(w, r)
			return
		}
		if _, pattern := mux.Handler(r); retiredPattern(pattern) {
			mux.ServeHTTP(w, r)
			return
		}
		caller := callerAddr(r)
		if agentLog.due(r.URL.Path+"\x00"+agent+"\x00"+caller, time.Now()) {
			slog.WarnContext(r.Context(), "rejected request without a named user agent",
				"method", r.Method, "path", r.URL.Path, "user_agent", agent,
				"caller", caller, "remote", r.RemoteAddr)
		}
		v1Error(w, http.StatusBadRequest, "user_agent_required",
			"Send a User-Agent naming your client and its version, such as forager/1.4.")
	})
}

// retiredPattern reports whether a mux pattern is one registerRetired added.
// Patterns name no method, so the pattern is the retired map's key.
func retiredPattern(pattern string) bool {
	_, ok := retired[pattern]
	return ok
}
