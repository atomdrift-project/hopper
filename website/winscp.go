package website

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

func newWinSCP() *winscp { return &winscp{page: winscpDownloadPage} }

const winscpDownloadPage = "https://winscp.net/eng/downloads.php"

type winscp struct {
	page string // overridable for tests
}

func (*winscp) Name() string          { return "winscp" }
func (*winscp) Hostname() string      { return "winscp.net" }
func (s *winscp) MonitorPage() string { return s.page }

// WinSCP's download page lists multiple "stable + beta" version cohorts. We
// pick the highest version that doesn't contain a beta/rc/alpha tag and
// return all artifacts (Setup.exe, .msi, Portable.zip, Automation.zip,
// Source.zip) for that version. The page also links to a bundled PuTTY
// installer; that's filtered out so we don't double-count.
// Matches WinSCP artifact links. Capture group 1 is the full href; capture
// group 2 is the dotted-int version (without any beta/rc tag); capture group
// 3 is the prerelease tag like ".beta" or empty for stable. Examples:
//
//	/download/WinSCP-6.5.6-Setup.exe/download         → v=6.5.6, tag=""
//	/download/WinSCP-6.5.6.msi/download               → v=6.5.6, tag=""
//	/download/WinSCP-6.6.1.beta-Setup.exe/download    → v=6.6.1, tag=".beta"
var winscpAssetRe = regexp.MustCompile(
	`href="(/download/WinSCP-(\d+(?:\.\d+)*)(\.beta|\.rc[0-9]*|\.alpha)?` +
		`(?:-[A-Za-z]+)?\.[A-Za-z0-9]+(?:/download)?)"`,
)

func (s *winscp) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.page, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // s.page is the configured download page.
	if err != nil {
		return nil, fmt.Errorf("download page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download page: HTTP %d", resp.StatusCode)
	}

	const maxBody = 2 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	// Find the highest non-pre-release version.
	var bestVersion string
	for _, m := range winscpAssetRe.FindAllSubmatch(body, -1) {
		v := string(m[2])
		if len(m[3]) != 0 { // any prerelease tag → skip
			continue
		}
		if bestVersion == "" || versionGreater(v, bestVersion) {
			bestVersion = v
		}
	}
	if bestVersion == "" {
		return nil, errors.New("no stable WinSCP version found")
	}

	pageURL := s.page
	host := "https://winscp.net"
	if i := strings.Index(pageURL, "://"); i >= 0 {
		if j := strings.Index(pageURL[i+3:], "/"); j >= 0 {
			host = pageURL[:i+3+j]
		}
	}

	// Each /download/<File>/download URL serves an HTML confirmation page
	// that links to the real CDN URL. Resolve each in a second pass.
	seen := map[string]bool{}
	var targets []Target
	for _, m := range winscpAssetRe.FindAllSubmatch(body, -1) {
		v, tag := string(m[2]), string(m[3])
		if v != bestVersion || tag != "" {
			continue
		}
		href := string(m[1])
		full := host + href
		if seen[full] {
			continue
		}
		seen[full] = true
		variant := winscpVariantFromHref(href)
		// ReadMe is a tiny .txt that shouldn't go through the
		// "click here" page; skip it entirely.
		if variant == "other" {
			continue
		}
		cdnURL, err := winscpResolveCDN(ctx, hc, full)
		if err != nil {
			// Don't fail the whole discovery if one artifact's
			// confirmation page glitches; let the engine surface
			// any retryable issue per-target on a future run.
			continue
		}
		targets = append(targets, Target{URL: cdnURL, Variant: variant})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no artifacts for WinSCP %s", bestVersion)
	}
	return targets, nil
}

// winscpCDNRe matches the cdn.winscp.net link inside a /download/<X>/download
// confirmation page. The URL has a short-lived ?secure=<token>,<timestamp>
// query string; treat it as ephemeral — Discover resolves it just before the
// engine fetches.
var winscpCDNRe = regexp.MustCompile(`href="(https://cdn\.winscp\.net/files/[^"]+)"`)

func winscpResolveCDN(ctx context.Context, hc *http.Client, confirmURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, confirmURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req) //nolint:gosec // confirmURL is constructed from the validated download page.
	if err != nil {
		return "", fmt.Errorf("confirm page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("confirm page: HTTP %d", resp.StatusCode)
	}
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	m := winscpCDNRe.FindSubmatch(body)
	if m == nil {
		return "", errors.New("no cdn.winscp.net link found")
	}
	return string(m[1]), nil
}

// versionGreater returns true if a > b under dotted-int comparison; falls
// back to string comparison when either fails to parse.
func versionGreater(a, b string) bool {
	ap, aok := parseDottedInts(a)
	bp, bok := parseDottedInts(b)
	if !aok || !bok {
		return a > b
	}
	return compareIntSlices(ap, bp) > 0
}

func winscpVariantFromHref(href string) string {
	switch {
	case strings.Contains(href, "-Portable"):
		return "portable"
	case strings.Contains(href, "-Automation"):
		return "automation"
	case strings.Contains(href, "-Source"):
		return "source"
	case strings.Contains(href, "-Setup.exe"):
		return "setup-exe"
	case strings.HasSuffix(href, ".msi/download"):
		return "msi"
	default:
		return "other"
	}
}
