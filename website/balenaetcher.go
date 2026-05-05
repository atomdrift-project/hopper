package website

import (
	"context"
	"net/http"
)

func newBalenaetcher() *balenaetcher { return &balenaetcher{} }

type balenaetcher struct{}

func (*balenaetcher) Name() string        { return "balenaetcher" }
func (*balenaetcher) Hostname() string    { return "etcher.balena.io" }
func (*balenaetcher) MonitorPage() string { return "https://etcher.balena.io/" }

func (*balenaetcher) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "balena-io/etcher")
}
