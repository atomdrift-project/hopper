package website

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

func newNodeJS() *nodejs { return &nodejs{page: nodejsLatestPage} }

const nodejsLatestPage = "https://nodejs.org/dist/latest/"

type nodejs struct {
	page string // overridable for tests
}

func (*nodejs) Name() string          { return "nodejs" }
func (*nodejs) Hostname() string      { return "nodejs.org" }
func (n *nodejs) MonitorPage() string { return n.page }

// Discovery: nodejs.org/dist/latest/ is an Apache-style directory listing
// whose content rotates as new releases ship. We grep for binary artifacts
// only; the page renders hrefs as absolute paths like
// "/dist/latest/node-v26.0.0-arm64.msi", so the regex captures the filename
// after the last slash rather than anchoring at the start of the href.
var nodejsAssetRe = regexp.MustCompile(`href="[^"]*/(node-v[^"/]+\.(?:msi|pkg|tar\.gz|tar\.xz|zip|7z|exe))"`)

func (n *nodejs) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.page, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req) //nolint:gosec // n.page is the configured Node.js dist index.
	if err != nil {
		return nil, fmt.Errorf("dist index: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dist index: HTTP %d", resp.StatusCode)
	}

	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	seen := map[string]bool{}
	var targets []Target
	for _, m := range nodejsAssetRe.FindAllSubmatch(body, -1) {
		filename := string(m[1])
		if seen[filename] {
			continue
		}
		seen[filename] = true
		targets = append(targets, Target{
			URL:     n.page + filename,
			Variant: filename,
		})
	}
	if len(targets) == 0 {
		return nil, errors.New("no node.js artifacts in dist/latest/ index")
	}
	return targets, nil
}
