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

func newWireshark() *wireshark { return &wireshark{page: wiresharkDownloadPage} }

const wiresharkDownloadPage = "https://www.wireshark.org/download.html"

type wireshark struct {
	page string // overridable for tests
}

func (*wireshark) Name() string          { return "wireshark" }
func (*wireshark) Hostname() string      { return "wireshark.org" }
func (s *wireshark) MonitorPage() string { return s.page }

// Discovery: the page lists both "Stable Release: X.Y.Z" and "Old Stable
// Release: X.Y.Z" sections, each containing the same set of artifact URLs
// for that version. We pick the version from the first heading and then
// collect every artifact URL containing that version. Same shape as 7-Zip.
//
// Wireshark binaries live on a CDN (2.na.dl.wireshark.org and similar),
// hostname normalized in our storage to wireshark.org.
var (
	wiresharkStableRe = regexp.MustCompile(`Stable Release:\s*([0-9.]+)`)
	wiresharkAssetRe  = regexp.MustCompile(`href="(https?://[^"]+\.dl\.wireshark\.org/[^"]+)"`)
)

func (s *wireshark) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
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

	const maxBody = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	m := wiresharkStableRe.FindSubmatch(body)
	if m == nil {
		return nil, errors.New("stable-release heading not found")
	}
	version := string(m[1])

	seen := map[string]bool{}
	var targets []Target
	for _, am := range wiresharkAssetRe.FindAllSubmatch(body, -1) {
		href := string(am[1])
		if !strings.Contains(href, version) || seen[href] {
			continue
		}
		seen[href] = true
		targets = append(targets, Target{URL: href, Variant: wiresharkVariant(href)})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no artifacts for stable %s", version)
	}
	return targets, nil
}

// wiresharkVariant labels by the path segment that follows the host: "win64",
// "osx", "src". Distinct enough for log lines without re-encoding the OS in
// the filename.
func wiresharkVariant(href string) string {
	_, rest, ok := strings.Cut(href, "://")
	if !ok {
		return "unknown"
	}
	_, rest, ok = strings.Cut(rest, "/")
	if !ok {
		return "unknown"
	}
	if seg, _, ok := strings.Cut(rest, "/"); ok {
		return seg
	}
	return rest
}
