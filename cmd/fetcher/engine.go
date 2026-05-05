package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/atomdrift/hopper/website"
)

const (
	userAgent      = "hopper-supply-chain-fetcher/0.1 (+https://codeberg.org/atomdrift/hopper)"
	discoverBudget = 30 * time.Second
	fetchBudget    = 30 * time.Minute
	maxBodyBytes   = int64(2 << 30) // 2 GiB
	// maxRedirects caps the redirect chain. Vendor download URLs sometimes
	// hop through 1-2 CDN signers (vendor → object store → signed CDN);
	// 3 is enough for the legitimate cases we've seen and short enough to
	// surface a misbehaving redirect loop quickly.
	maxRedirects = 3
)

// fetchResult is the metadata persisted in the sidecar JSON next to each
// archived binary. One sidecar per distinct sha256.
type fetchResult struct {
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	Source       string    `json:"source"`
	Hostname     string    `json:"hostname"`
	Variant      string    `json:"variant,omitempty"`
	MonitorPage  string    `json:"monitor_page,omitempty"`
	FetchURL     string    `json:"fetch_url"`
	FinalHost    string    `json:"final_host,omitempty"` // set only when redirect lands on a different host
	Filename     string    `json:"filename"`
	SHA256       string    `json:"sha256"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Server       string    `json:"server,omitempty"`
	SizeBytes    int64     `json:"size_bytes"`
}

// runSource discovers and (optionally) fetches everything for one Source.
// Errors from one target do not abort the others; they're logged and counted.
// When discoverOnly is true, the engine prints what would be fetched without
// reading any binary bodies — useful for surfacing extractor bugs before
// committing bandwidth.
func runSource(ctx context.Context, log *slog.Logger, hc *http.Client, s website.Source, outDir string, discoverOnly bool) error {
	log = log.With("source", s.Name(), "kind", website.KindOf(s))
	dctx, cancel := context.WithTimeout(ctx, discoverBudget)
	targets, err := s.Discover(dctx, hc)
	cancel()
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	log.Info("discovered", "targets", len(targets))

	if discoverOnly {
		for _, t := range targets {
			log.Info("would-fetch", "url", t.URL, "variant", t.Variant)
		}
		return nil
	}

	hostDir := filepath.Join(outDir, s.Hostname())
	if err := os.MkdirAll(hostDir, 0o750); err != nil {
		return err
	}

	var failed int
	for _, t := range targets {
		fctx, fcancel := context.WithTimeout(ctx, fetchBudget)
		err := fetchTarget(fctx, log, hc, s, t, hostDir)
		fcancel()
		if err != nil {
			log.Error("fetch", "url", t.URL, "variant", t.Variant, "err", err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d/%d targets failed", failed, len(targets))
	}
	return nil
}

// fetchTarget executes one HTTP GET, hashes the body to a temp file, and
// renames it into place as <sha256>-<filename>. The sidecar JSON is rewritten
// every fetch so last_seen_at advances; first_seen_at is preserved across
// re-observations of the same bytes. The gosec G304 suppression below is
// load-bearing: this tool exists to GET vendor-supplied URLs; per-host
// directory scoping plus sanitizeFilename keep writes contained.
//
//nolint:gosec // G304: vendor-supplied URLs are the input by design.
func fetchTarget(ctx context.Context, log *slog.Logger, hc *http.Client, s website.Source, t website.Target, hostDir string) error {
	log = log.With("variant", t.Variant)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, http.NoBody)
	if err != nil {
		return err
	}
	// Per-call client copy so we can install a redirect cap without
	// affecting the shared client used by other goroutines.
	hcCopy := *hc
	hcCopy.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
	resp, err := hcCopy.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", t.URL, err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", t.URL, resp.StatusCode)
	}

	filename := chooseFilename(t, resp)
	tmp, err := os.CreateTemp(hostDir, ".partial-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:errcheck // success path renames tmp away first

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(resp.Body, maxBodyBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("body read: %w", err)
	}
	if written > maxBodyBytes {
		return fmt.Errorf("body exceeds %d bytes", maxBodyBytes)
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	finalPath := filepath.Join(hostDir, sum+"-"+filename)
	sidecarPath := filepath.Join(hostDir, sum+".json")

	now := time.Now().UTC()
	res := fetchResult{
		FirstSeenAt:  now,
		LastSeenAt:   now,
		Source:       s.Name(),
		Hostname:     s.Hostname(),
		Variant:      t.Variant,
		MonitorPage:  s.MonitorPage(),
		FetchURL:     t.URL,
		FinalHost:    redirectHost(t.URL, resp.Request.URL),
		Filename:     filename,
		SHA256:       sum,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		Server:       resp.Header.Get("Server"),
		SizeBytes:    written,
	}

	// Idempotent on the binary: if we already have these bytes, drop the
	// temp file and only refresh the sidecar (preserving FirstSeenAt).
	if _, err := os.Stat(finalPath); err == nil {
		if prev, perr := readSidecar(sidecarPath); perr == nil && !prev.FirstSeenAt.IsZero() {
			res.FirstSeenAt = prev.FirstSeenAt
		}
		log.Info("unchanged", "sha256", sum, "size", written)
	} else {
		if err := os.Rename(tmpPath, finalPath); err != nil {
			return fmt.Errorf("rename to %s: %w", finalPath, err)
		}
		log.Info("stored", "sha256", sum, "size", written, "path", finalPath)
	}
	return writeSidecar(sidecarPath, &res)
}

// redirectHost returns the final host if it differs from the requested host,
// otherwise empty. It compresses the redirect chain into the one bit of
// signal that matters: did we end up on a different domain than we asked
// for? (Avoids polluting sidecars with megabyte-long signed CDN URLs.)
func redirectHost(requestedURL string, finalURL *url.URL) string {
	if finalURL == nil {
		return ""
	}
	req, err := url.Parse(requestedURL)
	if err != nil || req.Host == finalURL.Host {
		return ""
	}
	return finalURL.Host
}

// chooseFilename picks the on-disk basename for a target, in order:
// explicit Target.Filename → Content-Disposition filename* / filename →
// last path segment of the (final) URL. Falls back to "download" if none.
func chooseFilename(t website.Target, resp *http.Response) string {
	if t.Filename != "" {
		return sanitizeFilename(t.Filename)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if name := params["filename*"]; name != "" {
				return sanitizeFilename(name)
			}
			if name := params["filename"]; name != "" {
				return sanitizeFilename(name)
			}
		}
	}
	if u := resp.Request.URL; u != nil {
		if base := path.Base(u.Path); base != "" && base != "/" && base != "." {
			return sanitizeFilename(base)
		}
	}
	return "download"
}

// sanitizeFilename strips characters that would let a filename escape the
// per-host directory or collide with our sha256-prefix syntax.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	name = strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(name)
	name = strings.TrimLeft(name, ".")
	if name == "" {
		return "download"
	}
	return name
}

func writeSidecar(p string, res *fetchResult) error {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

func readSidecar(p string) (fetchResult, error) {
	var r fetchResult
	b, err := os.ReadFile(p)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	return r, nil
}

// newHTTPClient builds the shared client used for both discovery and fetch.
// Extractors call hc.Do without setting User-Agent themselves; transient 5xx
// or network errors are retried transparently.
func newHTTPClient() *http.Client {
	// Clone http.DefaultTransport so we own the *http.Transport instance and
	// can call CloseIdleConnections on it between retries.
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Should never happen with the stdlib default; falls back without
		// the close-idle behavior.
		return &http.Client{Transport: &retryTransport{base: &uaTransport{base: http.DefaultTransport}}}
	}
	tr := base.Clone()
	return &http.Client{
		Transport: &retryTransport{
			base:  &uaTransport{base: tr},
			inner: tr,
		},
	}
}

type uaTransport struct{ base http.RoundTripper }

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	return t.base.RoundTrip(req)
}

// retryTransport retries transient failures: any RoundTrip error, and any
// 5xx response. 4xx is the client's problem and is never retried. We only
// issue GETs with http.NoBody, so retrying is safe.
//
// Motivating case: nssm.cc fronts ~50% of requests with a broken nginx
// backend that returns 503 unconditionally; the other backend (Apache)
// serves correctly. Random per-connection LB selection. Without retries,
// our daily run would surface a false alert every other run. We force a
// fresh TCP connection between attempts via CloseIdleConnections so the
// LB picks again.
type retryTransport struct {
	base  http.RoundTripper
	inner *http.Transport // holds the actual conn pool, so we can flush it
}

const (
	retryAttempts = 5
	retryBase     = time.Second
)

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= retryAttempts; attempt++ {
		resp, err := t.base.RoundTrip(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			_ = resp.Body.Close() //nolint:errcheck // discarding before retry
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if attempt == retryAttempts {
			break
		}
		// Drop pooled connections so the next attempt dials fresh and gives
		// the upstream LB another chance to pick a different backend.
		if t.inner != nil {
			t.inner.CloseIdleConnections()
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(time.Duration(attempt) * retryBase):
		}
	}
	return nil, fmt.Errorf("after %d attempts: %w", retryAttempts, lastErr)
}
