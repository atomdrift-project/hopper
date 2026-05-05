package website

import (
	"context"
	"net/http"
)

func newBeekeeperstudio() *beekeeperstudio { return &beekeeperstudio{} }

type beekeeperstudio struct{}

func (*beekeeperstudio) Name() string        { return "beekeeperstudio" }
func (*beekeeperstudio) Hostname() string    { return "beekeeperstudio.io" }
func (*beekeeperstudio) MonitorPage() string { return "https://www.beekeeperstudio.io/" }

func (*beekeeperstudio) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "beekeeper-studio/beekeeper-studio")
}
