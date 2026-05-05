package website

import (
	"context"
	"net/http"
)

func newLighthouse() *lighthouse { return &lighthouse{} }

type lighthouse struct{}

func (*lighthouse) Name() string        { return "lighthouse" }
func (*lighthouse) Hostname() string    { return "lighthouse.sigmaprime.io" }
func (*lighthouse) MonitorPage() string { return "https://lighthouse-book.sigmaprime.io/" }

func (*lighthouse) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "sigp/lighthouse")
}
