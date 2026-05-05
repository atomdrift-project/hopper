package website

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
)

// githubReleaseBase is the production GitHub host. Tests override the base by
// calling githubReleaseAssetsAt directly with a httptest server URL.
const githubReleaseBase = "https://github.com"

// githubReleaseAssets returns the asset Targets for the latest release of the
// given GitHub repo. Pattern adapted from atomdrift/harvest/pkg/registry — no
// API key, no rate limit: HEAD /releases/latest to discover the tag from the
// redirect Location, then GET /releases/expanded_assets/<tag> and scrape the
// HTML for asset hrefs. The harvest version downloads files; we only collect
// URLs and let cmd/fetcher do the storage.
func githubReleaseAssets(ctx context.Context, hc *http.Client, repo string) ([]Target, error) {
	return githubReleaseAssetsAt(ctx, hc, githubReleaseBase, repo)
}

func githubReleaseAssetsAt(ctx context.Context, hc *http.Client, base, repo string) ([]Target, error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return nil, fmt.Errorf("repo must be \"owner/name\", got %q", repo)
	}
	tag, err := githubReleaseLatestTag(ctx, hc, base, owner, name)
	if err != nil {
		return nil, err
	}
	return githubReleaseScrapeAssets(ctx, hc, base, owner, name, tag)
}

// githubReleaseLatestTag follows the redirect from /<owner>/<name>/releases/latest
// to /<owner>/<name>/releases/tag/<TAG> and returns <TAG>. We issue a GET (since
// HEAD requires fiddling with the client's redirect policy) and discard the body.
func githubReleaseLatestTag(ctx context.Context, hc *http.Client, base, owner, name string) (string, error) {
	u := fmt.Sprintf("%s/%s/%s/releases/latest", base, owner, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req) //nolint:gosec // base is a configured host; owner/name are extractor constants.
	if err != nil {
		return "", fmt.Errorf("releases/latest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	_, _ = io.Copy(io.Discard, resp.Body)    //nolint:errcheck // body discarded; we only need final URL
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("releases/latest: HTTP %d", resp.StatusCode)
	}

	// After redirect-following, the URL path ends in /releases/tag/<TAG>.
	p := resp.Request.URL.Path
	const marker = "/releases/tag/"
	i := strings.LastIndex(p, marker)
	if i < 0 {
		return "", fmt.Errorf("no tag in final URL: %s", resp.Request.URL)
	}
	tag := p[i+len(marker):]
	if tag == "" {
		return "", fmt.Errorf("empty tag in %s", resp.Request.URL)
	}
	return tag, nil
}

// githubReleaseAssetHrefRe matches the href attributes on the expanded-assets
// fragment that point at release-download URLs. The fragment is server-rendered
// HTML embedded inside <details> elements on the main release page.
var githubReleaseAssetHrefRe = regexp.MustCompile(`href="(/[^"]+/releases/download/[^"]+)"`)

// githubReleaseScrapeAssets pulls /releases/expanded_assets/<tag> and extracts
// every download href. The 2 MB body cap matches harvest's; assets fragments
// for repos with 100+ assets stay well under that.
func githubReleaseScrapeAssets(ctx context.Context, hc *http.Client, base, owner, name, tag string) ([]Target, error) {
	u := fmt.Sprintf("%s/%s/%s/releases/expanded_assets/%s", base, owner, name, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // base/owner/name/tag are validated/derived above.
	if err != nil {
		return nil, fmt.Errorf("expanded_assets: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expanded_assets: HTTP %d", resp.StatusCode)
	}

	const maxBody = 2 << 20 // 2 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read assets fragment: %w", err)
	}

	matches := githubReleaseAssetHrefRe.FindAllSubmatch(body, -1)
	seen := make(map[string]bool, len(matches))
	targets := make([]Target, 0, len(matches))
	for _, m := range matches {
		href := string(m[1])
		if seen[href] {
			continue
		}
		seen[href] = true
		fname := path.Base(href)
		targets = append(targets, Target{
			URL:     "https://github.com" + href,
			Variant: githubReleaseVariant(fname),
		})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no assets in fragment for %s/%s@%s", owner, name, tag)
	}
	return targets, nil
}

// githubReleaseVariant strips the (possibly compound) extension from an asset
// filename to produce a short label for log lines. ".tar.xz" is treated as one
// extension; everything else falls through to LastIndex(".").
func githubReleaseVariant(filename string) string {
	for _, ext := range []string{".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst"} {
		if rest, ok := strings.CutSuffix(filename, ext); ok {
			return rest
		}
	}
	if i := strings.LastIndex(filename, "."); i > 0 {
		return filename[:i]
	}
	return filename
}
