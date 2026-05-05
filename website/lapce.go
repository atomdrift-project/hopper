package website

import (
	"context"
	"net/http"
)

func newLapce() *lapce { return &lapce{} }

type lapce struct{}

func (*lapce) Name() string        { return "lapce" }
func (*lapce) Hostname() string    { return "lapce.dev" }
func (*lapce) MonitorPage() string { return "https://lapce.dev/" }

func (*lapce) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "lapce/lapce")
}
