package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The API answers a client that names itself, refuses one that sends nothing
// or a library's default, and leaves the probes and the retired paths alone.
func TestAgentMiddleware(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/lookup", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /_/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	registerRetired(mux)
	handler := agentMiddleware(mux)

	for _, c := range []struct {
		path, agent string
		want        int
	}{
		{"/v1/lookup", "forager/1.4", http.StatusNoContent},
		{"/v1/lookup", "promoter (atomdrift sample triage)", http.StatusNoContent},
		{"/v1/lookup", "postdoc/0.9.0 (worker=nazgul)", http.StatusNoContent},
		{"/v1/lookup", "", http.StatusBadRequest},
		{"/v1/lookup", "   ", http.StatusBadRequest},
		{"/v1/lookup", "Go-http-client/1.1", http.StatusBadRequest},
		{"/v1/lookup", "curl/8.7.1", http.StatusBadRequest},
		{"/v1/lookup", "python-requests/2.32", http.StatusBadRequest},
		{"/v1/lookup", "reqwest/0.12", http.StatusBadRequest},
		{"/_/health", "", http.StatusNoContent},
		{"/api/next", "", http.StatusGone},
	} {
		r := httptest.NewRequest(http.MethodGet, c.path, http.NoBody)
		r.Header.Del("User-Agent")
		if c.agent != "" {
			r.Header.Set("User-Agent", c.agent)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != c.want {
			t.Errorf("%s with agent %q = %d, want %d", c.path, c.agent, rec.Code, c.want)
		}
	}
}

// hopper names itself when it calls an API.
func TestAuthorizeRequestNamesHopper(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/lookup", http.NoBody)
	authorizeRequest(r)
	if !namedAgent(r.UserAgent()) {
		t.Errorf("hopper's own agent %q would be refused", r.UserAgent())
	}
}
