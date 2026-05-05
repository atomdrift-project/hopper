package website

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// cpuidLatestAssets discovers the latest-version artifacts from a CPUID
// product page (cpuid.com/softwares/<slug>.html). The page layout is:
//
//	<div class="subtitle">Version <X.YY> for windows...</div>
//	<a href="/downloads/<slug>/<slug>_<X.YY>...exe">setup ...</a>
//	... a few sibling buttons for the same version ...
//	<h2>VERSIONS HISTORY</h2>
//	... older versions follow ...
//
// We parse the version from the subtitle and collect every download link
// containing that version string. Same shape as 7-Zip / Wireshark.
//
// Slug examples: "hwmonitor", "cpu-z", "perfmonitor-2".
func cpuidLatestAssets(ctx context.Context, hc *http.Client, slug string) ([]Target, error) {
	pageURL := fmt.Sprintf("https://www.cpuid.com/softwares/%s.html", slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // pageURL is built from a configured slug.
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

	versionRe := regexp.MustCompile(`<div class="subtitle">Version\s+(\d+(?:\.\d+)+)`)
	m := versionRe.FindSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("version subtitle not found on %s", pageURL)
	}
	version := string(m[1])

	// Match anchor hrefs whose path is /downloads/<slug>/<slug>_<version>...
	// Cover both relative (/downloads/...) and absolute (https://www.cpuid.com/downloads/...).
	pat := fmt.Sprintf(`href="((?:https?://www\.cpuid\.com)?/downloads/%s/%s_[^"]*%s[^"]*\.(?:exe|zip))"`,
		regexp.QuoteMeta(slug), regexp.QuoteMeta(slug), regexp.QuoteMeta(version))
	assetRe := regexp.MustCompile(pat)

	// www.cpuid.com/downloads/<...> serves a "click here to actually
	// download" intermediate HTML page; the real binary is at
	// download.cpuid.com/<...>. The two hosts share the same path layout,
	// so we just rewrite the host before returning.
	seen := map[string]bool{}
	var targets []Target
	for _, am := range assetRe.FindAllSubmatch(body, -1) {
		href := string(am[1])
		if !strings.HasPrefix(href, "http") {
			href = "https://www.cpuid.com" + href
		}
		href = strings.Replace(href, "://www.cpuid.com/downloads/", "://download.cpuid.com/", 1)
		if seen[href] {
			continue
		}
		seen[href] = true
		targets = append(targets, Target{URL: href, Variant: cpuidVariant(href, slug, version)})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no artifacts for %s %s", slug, version)
	}
	return targets, nil
}

// cpuidVariant labels by what's between "<slug>_<version>" and the extension.
//
//	cpu-z_2.19-en.exe       → "en.exe"
//	cpu-z_2.19-rog-en.zip   → "rog-en.zip"
//	hwmonitor_1.63.exe      → "exe"
//	hwmonitor_1.63.zip      → "zip"
func cpuidVariant(href, slug, version string) string {
	base := href
	if i := strings.LastIndex(href, "/"); i >= 0 {
		base = href[i+1:]
	}
	prefix := slug + "_" + version
	rest, ok := strings.CutPrefix(base, prefix)
	if !ok {
		return base
	}
	rest = strings.TrimPrefix(rest, "-")
	rest = strings.TrimPrefix(rest, ".")
	if rest == "" {
		return "default"
	}
	return rest
}
