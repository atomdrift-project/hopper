package website

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func newGolang() *golang { return &golang{api: golangDLJSON} }

const golangDLJSON = "https://go.dev/dl/?mode=json"

type golang struct {
	api string // overridable for tests
}

func (*golang) Name() string        { return "golang" }
func (*golang) Hostname() string    { return "go.dev" }
func (*golang) MonitorPage() string { return "https://go.dev/dl/" }

// Discovery: go.dev/dl/?mode=json returns the Go release index as JSON,
// newest first. We pick the first stable entry and emit one Target per file
// in its Files[] list. The JSON also publishes SHA-256 per file — a free
// integrity cross-check we can wire through later.
type golangFile struct {
	Filename string `json:"filename"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	SHA256   string `json:"sha256"`
	Kind     string `json:"kind"`
}

type golangVersion struct {
	Version string       `json:"version"`
	Files   []golangFile `json:"files"`
	Stable  bool         `json:"stable"`
}

func (g *golang) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req) //nolint:gosec // g.api is the configured Go dl JSON endpoint.
	if err != nil {
		return nil, fmt.Errorf("go dl: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go dl: HTTP %d", resp.StatusCode)
	}

	const maxBody = 4 << 20
	var versions []golangVersion
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&versions); err != nil {
		return nil, fmt.Errorf("go dl decode: %w", err)
	}

	// First stable entry (the index is newest-first).
	var current *golangVersion
	for i := range versions {
		if versions[i].Stable {
			current = &versions[i]
			break
		}
	}
	if current == nil {
		return nil, errors.New("no stable Go release in dl/?mode=json")
	}

	targets := make([]Target, 0, len(current.Files))
	for _, f := range current.Files {
		if f.Filename == "" {
			continue
		}
		variant := f.Kind
		if f.OS != "" || f.Arch != "" {
			variant = fmt.Sprintf("%s-%s-%s", f.OS, f.Arch, f.Kind)
		}
		targets = append(targets, Target{
			URL:     "https://go.dev/dl/" + f.Filename,
			Variant: variant,
		})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no files for stable Go %s", current.Version)
	}
	return targets, nil
}
