package main

// Bearer-token authentication for the work API.
//
// Hopper sits behind a Cloudflare tunnel, where cloudflared runs on this host
// and dials the API over loopback. Every remote request therefore arrives with
// a loopback peer address, so a loopback exemption would be an exemption for
// the whole internet: the token is required on every API route, local callers
// included — the local litmus worker among them.
//
// Only the liveness, readiness, and metrics probes are exempt, so monitoring,
// Prometheus, and the systemd watchdog work without holding a credential.
// None of them expose sample data. The HTML dashboard is not served by this
// listener at all; it has its own, bound to loopback by default.

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// minTokenLen is the shortest token accepted from --token-file. A short secret
// in front of a public tunnel is brute-forceable; the deploy scripts generate
// 64 hex characters.
const minTokenLen = 16

// authExemptPaths are the routes reachable without a bearer token. Matched
// exactly: a prefix match would exempt every route sharing the prefix.
var authExemptPaths = map[string]bool{
	"/healthz":  true,
	"/_/health": true,
	"/_/ready":  true,
	"/_/metrik": true,
}

// tokenDigest is the SHA-256 of the bearer token the API requires.
//
// The plaintext token is hashed when the digest is built and never stored, so
// it cannot reach a log line, a panic dump, or a core file. String redacts the
// digest as well: it is preimage-resistant, but there is no reason to print it.
type tokenDigest struct {
	sum [sha256.Size]byte
}

// newTokenDigest hashes a token read from --token-file.
func newTokenDigest(token string) (*tokenDigest, error) {
	if len(token) < minTokenLen {
		return nil, fmt.Errorf("token is %d bytes; at least %d required", len(token), minTokenLen)
	}
	return &tokenDigest{sum: sha256.Sum256([]byte(token))}, nil
}

// matches reports whether presented is the token this digest was built from.
// Both sides are hashed and the digests compared in constant time, so neither
// the expected token's length nor a shared prefix is observable in the
// response time.
func (d *tokenDigest) matches(presented []byte) bool {
	got := sha256.Sum256(presented)
	return subtle.ConstantTimeCompare(d.sum[:], got[:]) == 1
}

// String keeps the digest out of log lines and %v formatting.
func (*tokenDigest) String() string { return "tokenDigest(<redacted>)" }

// readTokenFile returns the first non-empty, trimmed line of path.
func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t, nil
		}
	}
	return "", errors.New("file is empty")
}

// loadTokenDigest reads the token at path and returns its digest.
//
// Every failure is an error rather than a nil digest: an operator who asked
// for authentication must never end up serving an open API because the token
// file went missing.
func loadTokenDigest(path string) (*tokenDigest, error) {
	token, err := readTokenFile(path)
	if err != nil {
		return nil, fmt.Errorf("--token-file %s: %w", path, err)
	}
	digest, err := newTokenDigest(token)
	if err != nil {
		return nil, fmt.Errorf("--token-file %s: %w", path, err)
	}
	return digest, nil
}

// bearerCredential returns the credential from an Authorization: Bearer
// header. The scheme is matched case-insensitively (RFC 9110 §11.1) and must
// be followed by exactly one space; the credential is returned verbatim and
// compared byte-exactly.
func bearerCredential(r *http.Request) ([]byte, bool) {
	const scheme = "Bearer "
	v := r.Header.Get("Authorization")
	if len(v) <= len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) {
		return nil, false
	}
	return []byte(v[len(scheme):]), true
}

// authMiddleware requires a bearer token on every request but authExemptPaths.
// A nil digest disables authentication and returns next unwrapped.
func authMiddleware(digest *tokenDigest, next http.Handler) http.Handler {
	if digest == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authExemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		cred, ok := bearerCredential(r)
		if !ok || !digest.matches(cred) {
			slog.WarnContext(r.Context(), "rejected request with missing or invalid bearer token",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", "Bearer")
			// One message for missing and invalid alike, so the endpoint is not
			// an oracle for whether a guessed token exists.
			http.Error(w, `{"error":"missing or invalid bearer token"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientToken is the bearer token this process presents when it *calls* a
// hopper API: the CLI subcommands (`triage`, `post-triage`, `demote-sighted`)
// that speak to a master over HTTP.
//
// $HOPPER_TOKEN wins, for callers that inject the token some other way;
// otherwise it is the first non-empty line of ~/.tok/hopper — the same file
// the deploy scripts install, and the same convention scan's worker uses
// (scan/src/upload.rs). An empty result means "no credential", which is
// correct against an unauthenticated master and earns an honest 401 against an
// authenticated one.
//
// Resolved once per process: a master reads its own copy once at startup too,
// so rotation is a restart on both ends.
var clientToken = sync.OnceValue(func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Debug("no home directory; API calls will carry no bearer token", "error", err)
		return resolveClientToken(os.Getenv("HOPPER_TOKEN"), "")
	}
	return resolveClientToken(os.Getenv("HOPPER_TOKEN"), filepath.Join(home, ".tok", "hopper"))
})

// resolveClientToken holds the precedence behind [clientToken], split out so it
// is testable without touching the process environment or the sync.Once.
func resolveClientToken(env, path string) string {
	if t := strings.TrimSpace(env); t != "" {
		return t
	}
	if path == "" {
		return ""
	}
	token, err := readTokenFile(path)
	if err != nil {
		return ""
	}
	return token
}

// authorizeRequest attaches this host's bearer token to an outgoing API
// request. A host with no token sends none — the master answers 401 if it
// wanted one, which is a clearer failure than a silently anonymous call.
func authorizeRequest(r *http.Request) {
	if token := clientToken(); token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
}
