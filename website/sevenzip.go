package website

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func newSevenZip() *sevenZip { return &sevenZip{page: sevenZipDownloadPage} }

const sevenZipDownloadPage = "https://www.7-zip.org/download.html"

type sevenZip struct {
	page string // overridable for tests
}

func (*sevenZip) Name() string          { return "7zip" }
func (*sevenZip) Hostname() string      { return "7-zip.org" }
func (s *sevenZip) MonitorPage() string { return s.page }

// Discovery flow:
//  1. GET https://www.7-zip.org/download.html (a static HTML page).
//  2. The first <P><B>Download 7-Zip <version> (<date>) for Windows</B></P>
//     names the current release; older versions appear in the same shape
//     lower on the page.
//  3. Every artifact for the current release is a <a href> containing
//     "/releases/download/<version>/" — the page redirects users to GitHub
//     Releases for the actual binaries.
//
// We collect every link matching the version path; this naturally excludes
// legacy versions and unrelated outbound links.
var sevenZipHeadingRe = regexp.MustCompile(`Download 7-Zip\s+(\S+)`)

func (s *sevenZip) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.page, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // s.page is the configured 7-Zip download page.
	if err != nil {
		return nil, fmt.Errorf("download page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download page: HTTP %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	var version string
	doc.Find("p > b").EachWithBreak(func(_ int, sel *goquery.Selection) bool {
		if m := sevenZipHeadingRe.FindStringSubmatch(sel.Text()); m != nil {
			version = m[1]
			return false
		}
		return true
	})
	if version == "" {
		return nil, errors.New("current-version heading not found")
	}

	needle := "/releases/download/" + version + "/"
	seen := map[string]bool{}
	var targets []Target
	doc.Find("a[href]").Each(func(_ int, sel *goquery.Selection) {
		href, _ := sel.Attr("href")
		if !strings.Contains(href, needle) || seen[href] {
			return
		}
		seen[href] = true
		targets = append(targets, Target{URL: href, Variant: sevenZipVariant(href, version)})
	})
	if len(targets) == 0 {
		return nil, fmt.Errorf("no artifacts for version %s", version)
	}
	return targets, nil
}

// sevenZipVariant derives a short label from a release URL, e.g.
//
//	".../26.01/7z2601-linux-x64.tar.xz"  → "linux-x64"
//	".../26.01/7z2601-x64.exe"           → "x64.exe"
//	".../26.01/7z2601.exe"               → "x86.exe"  (the bare 32-bit name)
//	".../26.01/7zr.exe"                  → "7zr.exe"  (no version prefix)
//	".../26.01/lzma2601.7z"              → "lzma.7z"
func sevenZipVariant(href, version string) string {
	base := href
	if i := strings.LastIndex(href, "/"); i >= 0 {
		base = href[i+1:]
	}
	flat := strings.ReplaceAll(version, ".", "")

	// Strip the "7z<flatVersion>" or "lzma<flatVersion>" prefix; what remains
	// is everything after the version stamp, with leading "-" or "." removed.
	for _, prefix := range []string{"7z" + flat, "lzma" + flat} {
		if rest, ok := strings.CutPrefix(base, prefix); ok {
			rest = strings.TrimPrefix(rest, "-")
			if rest == "" || strings.HasPrefix(rest, ".") {
				// Bare "7z2601.exe" → "x86.exe"; "lzma2601.7z" → "lzma.7z".
				if strings.HasPrefix(prefix, "7z") {
					return "x86" + rest
				}
				return "lzma" + rest
			}
			return rest
		}
	}
	return base
}
