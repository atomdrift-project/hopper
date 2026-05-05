package website

import (
	"context"
	"net/http"
)

func newInsomnia() *insomnia { return &insomnia{} }

type insomnia struct{}

func (*insomnia) Name() string        { return "insomnia" }
func (*insomnia) Hostname() string    { return "insomnia.rest" }
func (*insomnia) MonitorPage() string { return "https://insomnia.rest/download" }

func (*insomnia) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "Kong/insomnia")
}
