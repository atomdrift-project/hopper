package website

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

func newSignaldesktop() *signaldesktop { return &signaldesktop{base: signalUpdatesBase} }

const signalUpdatesBase = "https://updates.signal.org/desktop"

type signaldesktop struct {
	base string // overridable for tests
}

func (*signaldesktop) Name() string        { return "signaldesktop" }
func (*signaldesktop) Hostname() string    { return "signal.org" }
func (*signaldesktop) MonitorPage() string { return "https://signal.org/download/" }

// Signal Desktop ships via the electron-builder auto-update mechanism: the
// vendor publishes per-platform manifests at updates.signal.org/desktop/
// (latest.yml for Windows, latest-mac.yml, latest-linux.yml). Each names
// the current version, the per-architecture installer filenames, and a
// SHA-512 for each.
//
// GitHub Releases for signalapp/Signal-Desktop carries only auto-generated
// source archives, so the vendor's own update channel is the canonical
// distribution surface.
type signalManifest struct {
	Version string       `yaml:"version"`
	Files   []signalFile `yaml:"files"`
}

type signalFile struct {
	URL    string `yaml:"url"`
	SHA512 string `yaml:"sha512"`
	Size   int64  `yaml:"size"`
}

var signalManifests = []struct {
	manifest string
	platform string
}{
	{"latest.yml", "windows"},
	{"latest-mac.yml", "macos"},
	{"latest-linux.yml", "linux"},
}

func (s *signaldesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	seen := map[string]bool{}
	var targets []Target
	for _, m := range signalManifests {
		manifestURL := s.base + "/" + m.manifest
		files, err := signalFetchManifest(ctx, hc, manifestURL)
		if err != nil {
			// One platform's manifest going missing shouldn't block the
			// others; the engine will surface persistent issues on retry.
			continue
		}
		for _, f := range files {
			if f.URL == "" || seen[f.URL] {
				continue
			}
			seen[f.URL] = true
			targets = append(targets, Target{
				URL:     s.base + "/" + f.URL,
				Variant: m.platform + "-" + signalVariantHint(f.URL),
			})
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("no Signal manifests yielded files")
	}
	return targets, nil
}

func signalFetchManifest(ctx context.Context, hc *http.Client, url string) ([]signalFile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // url is constructed from the configured base.
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest: HTTP %d", resp.StatusCode)
	}

	const maxBody = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	var m signalManifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("manifest yaml: %w", err)
	}
	return m.Files, nil
}

// signalVariantHint extracts the architecture token from a Signal filename
// like "signal-desktop-win-arm64-8.8.0.exe" → "arm64".
func signalVariantHint(filename string) string {
	for _, arch := range []string{"arm64", "x64", "x86_64", "amd64", "i386"} {
		if strings.Contains(filename, "-"+arch+"-") {
			return arch
		}
	}
	return "default"
}
