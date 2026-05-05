package website

import (
	"context"
	"net/http"
)

func newCutter() *cutter { return &cutter{} }

type cutter struct{}

func (*cutter) Name() string        { return "cutter" }
func (*cutter) Hostname() string    { return "cutter.re" }
func (*cutter) MonitorPage() string { return "https://cutter.re/" }

func (*cutter) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "rizinorg/cutter")
}
