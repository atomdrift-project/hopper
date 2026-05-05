package website

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

func newNmap() *nmapSrc { return &nmapSrc{page: nmapDownloadPage} }

const nmapDownloadPage = "https://nmap.org/download.html"

type nmapSrc struct {
	page string // overridable for tests
}

func (*nmapSrc) Name() string          { return "nmap" }
func (*nmapSrc) Hostname() string      { return "nmap.org" }
func (s *nmapSrc) MonitorPage() string { return s.page }

// nmapAssetRe matches stable installer/source/binary anchors on the download
// page. The URLs we care about all live under nmap.org/dist/. The page mixes
// uppercase and lowercase HTML tag attributes, so the regex is case-insensitive.
var nmapAssetRe = regexp.MustCompile(`(?i)href="(https?://nmap\.org/dist/[^"]+\.(?:exe|dmg|tar\.bz2|tgz|tar\.gz|rpm|zip))"`)

func (s *nmapSrc) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
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

	seen := map[string]bool{}
	var targets []Target
	for _, m := range nmapAssetRe.FindAllSubmatch(body, -1) {
		href := string(m[1])
		if seen[href] {
			continue
		}
		seen[href] = true
		targets = append(targets, Target{URL: href, Variant: nmapVariantFromURL(href)})
	}
	if len(targets) == 0 {
		return nil, errors.New("no nmap.org/dist/ artifacts found")
	}
	return targets, nil
}

// nmapVariantFromURL produces a label from the trailing path segment, e.g.
// "nmap-7.99-setup.exe" → "windows-installer", "nmap-7.99.tgz" → "source-tgz".
// Falls back to the filename when the suffix is unfamiliar.
func nmapVariantFromURL(href string) string {
	switch {
	case endsAny(href, ".exe"):
		return "windows-installer"
	case endsAny(href, ".dmg"):
		return "macos"
	case endsAny(href, ".rpm"):
		return "linux-rpm"
	case endsAny(href, ".tar.bz2"):
		return "source-tar-bz2"
	case endsAny(href, ".tgz", ".tar.gz"):
		return "source-tgz"
	case endsAny(href, ".zip"):
		return "zip"
	default:
		return "default"
	}
}

func endsAny(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if len(s) >= len(suf) && s[len(s)-len(suf):] == suf {
			return true
		}
	}
	return false
}
