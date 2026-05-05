package website

import (
	"context"
	"net/http"
)

func newK3d() *k3d { return &k3d{} }

type k3d struct{}

func (*k3d) Name() string        { return "k3d" }
func (*k3d) Hostname() string    { return "k3d.io" }
func (*k3d) MonitorPage() string { return "https://k3d.io/" }

func (*k3d) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "k3d-io/k3d")
}
