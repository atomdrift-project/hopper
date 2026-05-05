package website

import (
	"context"
	"net/http"
)

func newSubfinder() *subfinder { return &subfinder{} }

type subfinder struct{}

func (*subfinder) Name() string        { return "subfinder" }
func (*subfinder) Hostname() string    { return "projectdiscovery.io/subfinder" }
func (*subfinder) MonitorPage() string { return "https://projectdiscovery.io/projects/subfinder" }

func (*subfinder) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "projectdiscovery/subfinder")
}
