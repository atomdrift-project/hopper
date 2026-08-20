package hopper

// token.go resolves the bearer token a process presents when it *calls* a
// hopper API. Every route on the work API requires one, so every client in the
// fleet — cyclotron, forager, promoter, prism, hopper's own CLI subcommands —
// needs the same answer to "which credential, from where". Keeping that answer
// here means a client repo attaches auth in one line and cannot drift from the
// convention the deploy scripts install against.

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// APIToken is the bearer token for outgoing hopper API calls.
//
// $HOPPER_TOKEN wins, for callers that inject the token some other way;
// otherwise it is the first non-empty line of ~/.tok/hopper — the same file
// the deploy scripts install, and the same convention scan's worker uses
// (scan/src/upload.rs). An empty result means "no credential", which is correct
// against an unauthenticated master and earns an honest 401 against an
// authenticated one.
//
// Resolved once per process: a master reads its own copy once at startup too,
// so rotation is a restart on both ends.
func APIToken() string { return apiToken() }

var apiToken = sync.OnceValue(func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Debug("no home directory; API calls will carry no bearer token", "error", err)
		return resolveAPIToken(os.Getenv("HOPPER_TOKEN"), "")
	}
	return resolveAPIToken(os.Getenv("HOPPER_TOKEN"), filepath.Join(home, ".tok", "hopper"))
})

// resolveAPIToken holds the precedence behind [APIToken], split out so it is
// testable without touching the process environment or the sync.Once.
func resolveAPIToken(env, path string) string {
	if t := strings.TrimSpace(env); t != "" {
		return t
	}
	if path == "" {
		return ""
	}
	token, err := ReadTokenFile(path)
	if err != nil {
		return ""
	}
	return token
}

// ReadTokenFile returns the first non-empty line of path, trimmed. Tokens are
// kept in single-line files that pick up a trailing newline from every editor
// and shell redirect that writes them, so the line — not the file — is the
// credential.
func ReadTokenFile(path string) (string, error) {
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

// Authorize attaches this host's bearer token to an outgoing API request. A
// host with no token sends none — the master answers 401 if it wanted one,
// which is a clearer failure than a silently anonymous call.
//
// Use it on hopper-bound requests only. Clients that share one http.Client
// across many hosts (forager's registry package, say) must not push this into a
// RoundTripper: that would hand the hopper token to every third party they
// fetch from.
func Authorize(r *http.Request) {
	if token := APIToken(); token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
}
