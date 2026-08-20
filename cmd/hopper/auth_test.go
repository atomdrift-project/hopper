package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef"

func testDigest(t *testing.T) *tokenDigest {
	t.Helper()
	d, err := newTokenDigest(testToken)
	if err != nil {
		t.Fatalf("newTokenDigest: %v", err)
	}
	return d
}

// okHandler records whether the request reached the wrapped handler.
func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestTokenDigestMatchesOnlyTheExactToken(t *testing.T) {
	d := testDigest(t)
	if !d.matches([]byte(testToken)) {
		t.Error("exact token rejected")
	}
	for _, presented := range []string{
		"",
		testToken[:len(testToken)-1],   // truncation
		testToken + "x",                // extension
		strings.ToUpper(testToken),     // case
		" " + testToken,                // leading space
		testToken[:16] + "00000000000", // shared prefix
	} {
		if d.matches([]byte(presented)) {
			t.Errorf("accepted wrong token %q", presented)
		}
	}
}

func TestTokenDigestRejectsShortTokens(t *testing.T) {
	if _, err := newTokenDigest(""); err == nil {
		t.Error("empty token accepted")
	}
	if _, err := newTokenDigest(strings.Repeat("a", minTokenLen-1)); err == nil {
		t.Error("short token accepted")
	}
	if _, err := newTokenDigest(strings.Repeat("a", minTokenLen)); err != nil {
		t.Errorf("minimum-length token rejected: %v", err)
	}
}

// The token must not be recoverable from a log line or a %v dump.
func TestTokenDigestStringRedacts(t *testing.T) {
	got := testDigest(t).String()
	if got != "tokenDigest(<redacted>)" {
		t.Errorf("String() = %q", got)
	}
	if strings.Contains(got, testToken) {
		t.Error("String() leaked the token")
	}
}

func TestLoadTokenDigestFailsClosed(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("tiny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "absent"), short} {
		digest, err := loadTokenDigest(path)
		if err == nil {
			t.Errorf("%s: accepted", path)
		}
		if digest != nil {
			t.Errorf("%s: returned a digest alongside an error", path)
		}
	}
}

// The case this exists for: cloudflared dials the API over loopback, so a
// loopback peer is not evidence of a local caller. The local litmus worker
// authenticates like everyone else.
func TestAuthMiddlewareRequiresTokenFromLoopback(t *testing.T) {
	reached := false
	h := authMiddleware(testDigest(t), okHandler(&reached))

	req := httptest.NewRequest(http.MethodGet, "/api/next", http.NoBody)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	if reached {
		t.Error("unauthenticated request reached the handler")
	}
}

func TestAuthMiddlewareRejectsBadCredentials(t *testing.T) {
	for _, header := range []string{
		"",
		"Bearer wrong-token-wrong-token",
		"Basic " + testToken,
		testToken,
		"Bearer" + testToken,
		"Bearer ",
		"Bearer",
		"Bearer " + testToken[:len(testToken)-1],
		"Bearer " + testToken + "x",
		"Bearer " + strings.ToUpper(testToken),
	} {
		reached := false
		h := authMiddleware(testDigest(t), okHandler(&reached))
		req := httptest.NewRequest(http.MethodPost, "/api/result", http.NoBody)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, rec.Code)
		}
		if reached {
			t.Errorf("header %q: reached the handler", header)
		}
	}
}

func TestAuthMiddlewareAcceptsValidToken(t *testing.T) {
	// RFC 9110 §11.1: the scheme is case-insensitive.
	for _, header := range []string{"Bearer " + testToken, "bearer " + testToken} {
		reached := false
		h := authMiddleware(testDigest(t), okHandler(&reached))
		req := httptest.NewRequest(http.MethodGet, "/api/next", http.NoBody)
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !reached {
			t.Errorf("header %q: status = %d, reached = %v", header, rec.Code, reached)
		}
	}
}

// Probes stay open so monitoring, Prometheus, and the systemd watchdog work
// without holding a credential. None of them expose sample data.
func TestAuthMiddlewareExemptsProbes(t *testing.T) {
	for path := range authExemptPaths {
		reached := false
		h := authMiddleware(testDigest(t), okHandler(&reached))
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !reached {
			t.Errorf("%s: status = %d, reached = %v", path, rec.Code, reached)
		}
	}
}

// The exemption is an exact match. A prefix match would open every route
// sharing a prefix with a probe.
func TestAuthMiddlewareExemptionIsExact(t *testing.T) {
	for _, path := range []string{
		"/healthz/../api/next",
		"/healthzz",
		"/healthz/x",
		"/_/healthz",
		"/_/metrikk",
		"/",
		"/api/next",
	} {
		reached := false
		h := authMiddleware(testDigest(t), okHandler(&reached))
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", path, rec.Code)
		}
		if reached {
			t.Errorf("%s: reached the handler", path)
		}
	}
}

// Without --token-file the API behaves exactly as it did before tokens
// existed, so the middleware is a no-op rather than a silent deny.
func TestAuthMiddlewareNilDigestIsPassthrough(t *testing.T) {
	reached := false
	inner := okHandler(&reached)
	if got := authMiddleware(nil, inner); fmt.Sprintf("%p", got) != fmt.Sprintf("%p", inner) {
		t.Error("nil digest should return the handler unwrapped")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/next", http.NoBody)
	rec := httptest.NewRecorder()
	authMiddleware(nil, inner).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Errorf("status = %d, reached = %v", rec.Code, reached)
	}
}

// The two halves have to meet: a request stamped by authorizeRequest must be
// one that authMiddleware accepts. Without this, each side can be individually
// correct while the CLI still 401s against its own master.
func TestAuthorizeRequestSatisfiesTheMiddleware(t *testing.T) {
	restore := clientToken
	t.Cleanup(func() { clientToken = restore })
	clientToken = func() string { return testToken }

	req := httptest.NewRequest(http.MethodPost, "/api/triage", http.NoBody)
	authorizeRequest(req)
	if got := req.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Fatalf("Authorization = %q", got)
	}

	reached := false
	rec := httptest.NewRecorder()
	authMiddleware(testDigest(t), okHandler(&reached)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Errorf("status = %d, reached = %v; the CLI cannot reach its own API", rec.Code, reached)
	}
}

// A host with no token sends no header, so an unauthenticated master keeps
// working exactly as before.
func TestAuthorizeRequestWithoutATokenSendsNoHeader(t *testing.T) {
	restore := clientToken
	t.Cleanup(func() { clientToken = restore })
	clientToken = func() string { return "" }

	req := httptest.NewRequest(http.MethodGet, "/api/file/abc", http.NoBody)
	authorizeRequest(req)
	if got, ok := req.Header["Authorization"]; ok {
		t.Errorf("Authorization set without a token: %q", got)
	}
}
