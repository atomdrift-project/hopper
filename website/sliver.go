package website

import (
	"context"
	"net/http"
)

func newSliver() *sliver { return &sliver{} }

type sliver struct{}

func (*sliver) Name() string        { return "sliver" }
func (*sliver) Hostname() string    { return "github.com/BishopFox/sliver" }
func (*sliver) MonitorPage() string { return "https://github.com/BishopFox/sliver/releases" }

// Sliver — adversary-emulation C2 framework, published by BishopFox.
func (*sliver) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "BishopFox/sliver")
}
