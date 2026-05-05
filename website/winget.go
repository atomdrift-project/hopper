package website

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// The winget shadow-source helper. Vendors whose download pages are gated by
// Cloudflare or otherwise unscrapeable can be monitored through Microsoft's
// public winget-pkgs manifest repo, which names the same canonical installer
// URL the user would otherwise click through a browser to obtain. The
// manifest also publishes a vendor-blessed InstallerSha256 — a free
// integrity cross-check we can validate our download against (the engine
// records the claimed SHA in the sidecar; mismatch is itself a supply-chain
// signal worth alerting on).
//
// Two HTTP calls per discovery:
//  1. List version subdirectories by scraping the embedded JSON payload in
//     https://github.com/microsoft/winget-pkgs/tree/master/manifests/<l>/<P1>/<P2>
//     (avoids the 60-req/hr anonymous rate limit on the Contents API).
//  2. Fetch the installer YAML manifest from
//     https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/<l>/<P1>/<P2>/<version>/<P1>.<P2>.installer.yaml

const (
	wingetTreeBase = "https://github.com/microsoft/winget-pkgs/tree/master/manifests"
	wingetRawBase  = "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests"
)

// wingetInstallerURLs returns one Target per Installer entry in the latest
// manifest for packageID (e.g. "REALiX.HWiNFO" → "r/REALiX/HWiNFO" path).
// The Variant column carries the architecture; Filename is left to the
// engine to derive from URL or Content-Disposition.
func wingetInstallerURLs(ctx context.Context, hc *http.Client, packageID string) ([]Target, error) {
	return wingetInstallerURLsAt(ctx, hc, wingetTreeBase, wingetRawBase, packageID)
}

func wingetInstallerURLsAt(ctx context.Context, hc *http.Client, treeBase, rawBase, packageID string) ([]Target, error) {
	wp, err := wingetPackagePath(packageID)
	if err != nil {
		return nil, err
	}

	versions, err := wingetListVersions(ctx, hc, treeBase, wp.dir, wp.p1, wp.p2)
	if err != nil {
		return nil, err
	}
	latest := pickLatestVersion(versions)
	if latest == "" {
		return nil, fmt.Errorf("winget %s: no parseable version among %v", packageID, versions)
	}

	manifestURL := fmt.Sprintf("%s/%s/%s/%s/%s/%s.%s.installer.yaml",
		rawBase, wp.dir, wp.p1, wp.p2, latest, wp.p1, wp.p2)
	return wingetFetchManifest(ctx, hc, manifestURL, packageID, latest)
}

type wingetPath struct{ dir, p1, p2 string }

// wingetPackagePath splits "REALiX.HWiNFO" into (firstLetterDir, p1, p2).
// winget-pkgs paths are case-preserving; "r/REALiX/HWiNFO".
func wingetPackagePath(packageID string) (wingetPath, error) {
	p1, p2, ok := strings.Cut(packageID, ".")
	if !ok || p1 == "" || p2 == "" {
		return wingetPath{}, fmt.Errorf("packageID must be \"Publisher.Name\", got %q", packageID)
	}
	return wingetPath{dir: strings.ToLower(string(p1[0])), p1: p1, p2: p2}, nil
}

// wingetTreeItemRe matches the embedded-JSON form GitHub uses on tree pages:
// {"name":"X","path":"PATH","contentType":"directory"}. The page also embeds
// the root and parent trees for sidebar navigation, so we capture the path
// and filter by prefix in wingetListVersions to keep only the target dir's
// children.
var wingetTreeItemRe = regexp.MustCompile(`"name":"([^"]+)","path":"([^"]+)","contentType":"directory"`)

func wingetListVersions(ctx context.Context, hc *http.Client, treeBase, dir, p1, p2 string) ([]string, error) {
	u := fmt.Sprintf("%s/%s/%s/%s", treeBase, dir, p1, p2)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // treeBase + derived path; both validated above.
	if err != nil {
		return nil, fmt.Errorf("tree page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tree page: HTTP %d", resp.StatusCode)
	}

	const maxBody = 4 << 20 // 4 MiB; large package dirs may have hundreds of versions.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("tree page read: %w", err)
	}

	pathPrefix := fmt.Sprintf("manifests/%s/%s/%s/", dir, p1, p2)
	matches := wingetTreeItemRe.FindAllSubmatch(body, -1)
	versions := make([]string, 0, len(matches))
	for _, m := range matches {
		name, p := string(m[1]), string(m[2])
		if !strings.HasPrefix(p, pathPrefix) {
			continue
		}
		if name == "" || name[0] == '.' {
			continue
		}
		versions = append(versions, name)
	}
	if len(versions) == 0 {
		return nil, errors.New("tree page: no version directories")
	}
	return versions, nil
}

type wingetInstaller struct {
	Architecture   string `yaml:"Architecture"`
	InstallerType  string `yaml:"InstallerType"`
	InstallerURL   string `yaml:"InstallerUrl"`
	InstallerSHA   string `yaml:"InstallerSha256"`
	InstallerLocal string `yaml:"InstallerLocale"`
}

type wingetManifest struct {
	PackageIdentifier string            `yaml:"PackageIdentifier"`
	PackageVersion    string            `yaml:"PackageVersion"`
	Installers        []wingetInstaller `yaml:"Installers"`
}

func wingetFetchManifest(ctx context.Context, hc *http.Client, manifestURL, packageID, version string) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // manifestURL is constructed from validated package fields.
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest %s: HTTP %d", manifestURL, resp.StatusCode)
	}

	const maxBody = 1 << 20 // 1 MiB; manifests are typically a few KB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("manifest read: %w", err)
	}

	var m wingetManifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("manifest yaml: %w", err)
	}
	if len(m.Installers) == 0 {
		return nil, fmt.Errorf("manifest %s/%s: no installers", packageID, version)
	}

	seen := make(map[string]bool, len(m.Installers))
	var targets []Target
	for _, ins := range m.Installers {
		if ins.InstallerURL == "" || seen[ins.InstallerURL] {
			continue
		}
		seen[ins.InstallerURL] = true
		variant := ins.Architecture
		if variant == "" {
			variant = "default"
		}
		targets = append(targets, Target{URL: ins.InstallerURL, Variant: variant})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("manifest %s/%s: no usable installer URLs", packageID, version)
	}
	return targets, nil
}

// pickLatestVersion returns the highest "dotted-integer" version among xs,
// e.g. "8.46" beats "8.42". Falls back to lexicographic for ties / parses.
// Strings that don't begin with a digit (after an optional 'v' prefix) are
// skipped — winget version strings are well-behaved enough that this covers
// the realistic cases.
func pickLatestVersion(xs []string) string {
	var best string
	var bestParts []int
	for _, x := range xs {
		parts, ok := parseDottedInts(x)
		if !ok {
			continue
		}
		if best == "" || compareIntSlices(parts, bestParts) > 0 ||
			(compareIntSlices(parts, bestParts) == 0 && x > best) {
			best = x
			bestParts = parts
		}
	}
	return best
}

// parseDottedInts splits "8.46" → [8,46], "v1.2.3" → [1,2,3]. Returns ok=false
// for strings with non-digit components.
func parseDottedInts(s string) ([]int, bool) {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
		for _, r := range p {
			if !unicode.IsDigit(r) {
				return nil, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func compareIntSlices(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
