package website

import (
	"context"
	"net/http"
)

func newZed() *zed { return &zed{} }

type zed struct{}

func (*zed) Name() string        { return "zed" }
func (*zed) Hostname() string    { return "zed.dev" }
func (*zed) MonitorPage() string { return "https://zed.dev/" }

func (*zed) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "zed-industries/zed")
}
