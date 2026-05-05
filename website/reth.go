package website

import (
	"context"
	"net/http"
)

func newReth() *reth { return &reth{} }

type reth struct{}

func (*reth) Name() string        { return "reth" }
func (*reth) Hostname() string    { return "paradigmxyz.github.io/reth" }
func (*reth) MonitorPage() string { return "https://github.com/paradigmxyz/reth/releases" }

func (*reth) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "paradigmxyz/reth")
}
