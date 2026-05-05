package website

import (
	"context"
	"net/http"
)

func newNuclei() *nuclei { return &nuclei{} }

type nuclei struct{}

func (*nuclei) Name() string        { return "nuclei" }
func (*nuclei) Hostname() string    { return "projectdiscovery.io/nuclei" }
func (*nuclei) MonitorPage() string { return "https://projectdiscovery.io/projects/nuclei" }

// Nuclei — fast template-based vulnerability scanner from ProjectDiscovery.
func (*nuclei) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "projectdiscovery/nuclei")
}
