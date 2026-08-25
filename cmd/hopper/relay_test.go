package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newRelayPrimary is a stand-in primary that records what reached it and
// answers with a distinctive status/body so tests can prove verbatim
// propagation.
type recordedRequest struct {
	method, path, query, body, auth, lane, xff string
}

func newRelayPrimary(t *testing.T, status int, respBody string) (*httptest.Server, *recordedRequest) {
	t.Helper()
	rec := &recordedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body) //nolint:errcheck // test stub
		*rec = recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			body:   string(b),
			auth:   r.Header.Get("Authorization"),
			lane:   r.Header.Get(laneHeader),
			xff:    r.Header.Get("X-Forwarded-For"),
		}
		w.Header().Set("X-Hopper-Source", "primary")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody)) //nolint:errcheck // test stub
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// newReplicaMux builds the route table exactly as serve-replica does, with an
// optional relay, so tests exercise the real registerAPI classification.
func newReplicaMux(t *testing.T, relayBase, relayTokenFile string) *http.ServeMux {
	t.Helper()
	api := &apiServer{readOnly: true, tracker: newWorkerTracker()}
	if relayBase != "" {
		relay, err := newWriteRelay(relayBase, relayTokenFile)
		if err != nil {
			t.Fatalf("newWriteRelay(%q): %v", relayBase, err)
		}
		api.relay = relay
	}
	mux := http.NewServeMux()
	api.registerAPI(mux)
	return mux
}

// TestReplicaWithoutRelayRefusesAllMutations pins the pre-relay behavior: no
// relay configured means every mutating route answers 403, exactly as before.
func TestReplicaWithoutRelayRefusesAllMutations(t *testing.T) {
	mux := newReplicaMux(t, "", "")
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/next"},
		{http.MethodGet, "/api/heartbeat"},
		{http.MethodPost, "/api/result"},
		{http.MethodPost, "/api/upload"},
		{http.MethodPost, "/api/known"},
		{http.MethodPost, "/api/sightings"},
		{http.MethodPost, "/api/popular"},
		{http.MethodPost, "/api/triage"},
		{http.MethodPost, "/api/rescan/" + strings.Repeat("a", 64)},
		{http.MethodPost, "/api/report"},
		{http.MethodPost, "/api/cleave-result"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(ep.method, ep.path, http.NoBody))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s without relay = %d, want 403", ep.method, ep.path, w.Code)
		}
	}
}

// TestRelayProxiesTriageWrites covers the two triage-consumer mutations added
// with the queue registry. They are client-facing writes, so they relay like
// the rest — the point of which is that a scan host can address ONE URL for
// its selections and its judgements both.
func TestRelayProxiesTriageWrites(t *testing.T) {
	for _, path := range []string{"/api/report", "/api/cleave-result"} {
		primary, rec := newRelayPrimary(t, http.StatusOK, `{"status":"recorded"}`)
		mux := newReplicaMux(t, primary.URL, "")

		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"sha256":"x"}`)))
		if w.Code != http.StatusOK {
			t.Errorf("POST %s via relay = %d, want the primary's 200", path, w.Code)
		}
		if rec.path != path || rec.method != http.MethodPost {
			t.Errorf("primary saw (%s %s), want POST %s", rec.method, rec.path, path)
		}
	}
}

// TestRelayProxiesClientWritesVerbatim is the core contract: a client-facing
// mutation reaches the primary with method, path, query, body, Authorization
// and lane header intact, plus X-Forwarded-For, and the primary's response
// comes back untouched.
func TestRelayProxiesClientWritesVerbatim(t *testing.T) {
	primary, rec := newRelayPrimary(t, http.StatusCreated, `{"stored":true}`)
	mux := newReplicaMux(t, primary.URL, "")

	req := httptest.NewRequest(http.MethodPost, "/api/upload?feed=osv", strings.NewReader("payload-bytes"))
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set(laneHeader, "renew")
	req.RemoteAddr = "10.9.8.60:41234"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("relayed status = %d, want 201; body %s", w.Code, w.Body.String())
	}
	if w.Body.String() != `{"stored":true}` {
		t.Errorf("relayed body = %q, want primary's body verbatim", w.Body.String())
	}
	if rec.method != http.MethodPost || rec.path != "/api/upload" || rec.query != "feed=osv" {
		t.Errorf("primary saw %s %s?%s, want POST /api/upload?feed=osv", rec.method, rec.path, rec.query)
	}
	if rec.body != "payload-bytes" {
		t.Errorf("primary saw body %q, want payload-bytes", rec.body)
	}
	if rec.auth != "Bearer client-token" {
		t.Errorf("primary saw Authorization %q, want the client's token passed through", rec.auth)
	}
	if rec.lane != "renew" {
		t.Errorf("primary saw lane %q, want renew (lane semantics must survive the hop)", rec.lane)
	}
	if !strings.HasPrefix(rec.xff, "10.9.8.60") {
		t.Errorf("primary saw X-Forwarded-For %q, want the client address", rec.xff)
	}
}

// TestRelayPropagatesPrimaryShedVerbatim: the 503 slot-shed answer must reach
// the client exactly as the primary sent it — lane retry semantics depend on
// clients seeing it honestly, and the relay must never rewrite or retry it.
func TestRelayPropagatesPrimaryShedVerbatim(t *testing.T) {
	primary, _ := newRelayPrimary(t, http.StatusServiceUnavailable, `{"error":"ingestion slots saturated"}`)
	mux := newReplicaMux(t, primary.URL, "")

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/triage", strings.NewReader("{}")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("shed status = %d, want the primary's 503 verbatim", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ingestion slots saturated") {
		t.Errorf("shed body = %q, want the primary's body verbatim", w.Body.String())
	}
}

// TestRelayNeverServesWorkerRoutes: rule 2 — the worker loop is refused even
// with a healthy relay configured, so result envelopes cannot double-hop
// through the replica. The one carve-out is the renew lane on /api/result:
// single-artifact renewals relay so a serve host can use the replica URL for
// everything, while an undeclared (worker-lane) result stays refused.
func TestRelayNeverServesWorkerRoutes(t *testing.T) {
	primary, rec := newRelayPrimary(t, http.StatusOK, "worker lane must never reach this")
	mux := newReplicaMux(t, primary.URL, "")

	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/next"},
		{http.MethodGet, "/api/heartbeat"},
		{http.MethodPost, "/api/result"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(ep.method, ep.path, http.NoBody))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s with relay = %d, want 403", ep.method, ep.path, w.Code)
		}
	}
	if rec.method != "" {
		t.Errorf("primary was reached by a worker route (%s %s); worker routes must never relay", rec.method, rec.path)
	}

	// The renew lane relays.
	req := httptest.NewRequest(http.MethodPost, "/api/result", strings.NewReader("{}"))
	req.Header.Set(laneHeader, "renew")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("renew-lane result via relay = %d, want the primary's 200", w.Code)
	}
	if rec.path != "/api/result" || rec.lane != "renew" {
		t.Errorf("primary saw (%s, lane=%s), want /api/result with the renew lane intact", rec.path, rec.lane)
	}

	// Without a relay, the renew lane is refused like everything else.
	noRelay := newReplicaMux(t, "", "")
	w = httptest.NewRecorder()
	noRelay.ServeHTTP(w, req.Clone(t.Context()))
	if w.Code != http.StatusForbidden {
		t.Errorf("renew-lane result without relay = %d, want 403", w.Code)
	}
}

// TestRelayUnreachablePrimaryIs502: reachability failures are the relay's own
// (502), distinct from anything the primary said.
func TestRelayUnreachablePrimaryIs502(t *testing.T) {
	// A closed port: reserve one with a listener, then close it.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	mux := newReplicaMux(t, deadURL, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/known", strings.NewReader("{}")))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("unreachable primary = %d, want 502", w.Code)
	}
	if !strings.Contains(w.Body.String(), "primary hopper unreachable") {
		t.Errorf("502 body = %q, want the relay's own error", w.Body.String())
	}
}

// TestRelayTokenFileReplacesAuthorization: with --relay-token-file, the
// primary sees the configured token, not the client's.
func TestRelayTokenFileReplacesAuthorization(t *testing.T) {
	primary, rec := newRelayPrimary(t, http.StatusOK, "{}")
	tokPath := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokPath, []byte("primary-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mux := newReplicaMux(t, primary.URL, tokPath)

	req := httptest.NewRequest(http.MethodPost, "/api/sightings", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer replica-local-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("relayed status = %d, want 200", w.Code)
	}
	if rec.auth != "Bearer primary-secret" {
		t.Errorf("primary saw Authorization %q, want the relay token to replace the client's", rec.auth)
	}
}

// TestFreshQueryRoutesLookupToPrimary: the read-after-write escape hatch.
// ?fresh=1 and X-Hopper-Fresh: 1 route the lookup through the relay; a plain
// lookup stays local; and with no relay configured the flag is a no-op.
func TestFreshQueryRoutesLookupToPrimary(t *testing.T) {
	primary, rec := newRelayPrimary(t, http.StatusOK, `{"from":"primary"}`)
	relay, err := newWriteRelay(primary.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	localHits := 0
	local := func(w http.ResponseWriter, _ *http.Request) {
		localHits++
		_, _ = w.Write([]byte(`{"from":"replica"}`)) //nolint:errcheck // test stub
	}

	s := &apiServer{readOnly: true, relay: relay}
	h := s.freshOr(local)

	for _, tt := range []struct {
		name       string
		target     string
		freshHdr   bool
		wantOrigin string
	}{
		{"plain stays local", "/api/sample/abc", false, "replica"},
		{"fresh=1 goes to primary", "/api/sample/abc?fresh=1", false, "primary"},
		{"header goes to primary", "/api/sample/abc", true, "primary"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, http.NoBody)
			if tt.freshHdr {
				req.Header.Set("X-Hopper-Fresh", "1")
			}
			w := httptest.NewRecorder()
			h(w, req)
			if !strings.Contains(w.Body.String(), tt.wantOrigin) {
				t.Errorf("body = %q, want served by %s", w.Body.String(), tt.wantOrigin)
			}
			wantSource := "primary"
			if tt.wantOrigin == "replica" {
				wantSource = "replica"
			}
			if got := w.Header().Get("X-Hopper-Source"); got != wantSource {
				t.Errorf("source header = %q, want %q", got, wantSource)
			}
		})
	}
	if localHits != 1 {
		t.Errorf("local handler hits = %d, want exactly 1 (the plain lookup)", localHits)
	}
	if rec.query != "fresh=1" && rec.path == "" {
		t.Error("primary never saw the fresh lookup")
	}

	// No relay configured: fresh=1 is a no-op and the local handler serves.
	noRelay := &apiServer{readOnly: true}
	w := httptest.NewRecorder()
	noRelay.freshOr(local)(w, httptest.NewRequest(http.MethodGet, "/api/sample/abc?fresh=1", http.NoBody))
	if !strings.Contains(w.Body.String(), "replica") {
		t.Errorf("fresh without relay = %q, want local serve", w.Body.String())
	}
}

// TestNewWriteRelayRejectsBadBases: a pathed or garbage base is a config
// error at startup, not a surprise at request time.
func TestNewWriteRelayRejectsBadBases(t *testing.T) {
	for _, base := range []string{
		"", "hopper-api:8081", "http://hopper-api:8081/api", "://nope",
	} {
		if _, err := newWriteRelay(base, ""); err == nil {
			t.Errorf("newWriteRelay(%q) succeeded, want error", base)
		}
	}
	// And the canonical forms are accepted.
	for _, base := range []string{"http://hopper-api:8081", "http://hopper-api:8081/"} {
		if _, err := newWriteRelay(base, ""); err != nil {
			t.Errorf("newWriteRelay(%q): %v, want ok", base, err)
		}
	}
}
