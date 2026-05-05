package website

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"

	"github.com/PuerkitoBio/goquery"
)

func newNSSM() *nssm { return &nssm{page: nssmDownloadPage} }

const nssmDownloadPage = "https://nssm.cc/download"

type nssm struct {
	page string // overridable for tests
}

func (*nssm) Name() string          { return "nssm" }
func (*nssm) Hostname() string      { return "nssm.cc" }
func (s *nssm) MonitorPage() string { return s.page }

// nssmAssetPathRe matches a relative href like "/release/nssm-2.24.zip" or
// "/ci/nssm-2.24-101-g897c7ad.zip". The page only links to two artifacts —
// the latest stable release and the featured prerelease — but we don't pin
// to specific filenames since the version string changes when they update.
var nssmAssetPathRe = regexp.MustCompile(`^/(release|ci)/nssm-[^/]+\.zip$`)

// Discovery: NSSM's download page is a tiny static HTML page that links
// directly to two zip files. The page calls them "Latest release" and
// "Featured pre-release"; the headings are <h4> blocks but the links are the
// only things on the page matching the asset-path pattern, so we filter by
// path regex rather than walking the DOM.
func (s *nssm) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
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

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	pageURL, err := url.Parse(s.page)
	if err != nil {
		return nil, fmt.Errorf("parse monitor page URL: %w", err)
	}

	seen := map[string]bool{}
	var targets []Target
	doc.Find("a[href]").Each(func(_ int, sel *goquery.Selection) {
		href, _ := sel.Attr("href")
		if !nssmAssetPathRe.MatchString(href) || seen[href] {
			return
		}
		seen[href] = true

		abs := *pageURL
		abs.Path = href
		variant := "release"
		if href[1:3] == "ci" {
			variant = "prerelease"
		}
		targets = append(targets, Target{URL: abs.String(), Variant: variant})
	})
	if len(targets) == 0 {
		return nil, errors.New("no NSSM zip links found")
	}
	return targets, nil
}
