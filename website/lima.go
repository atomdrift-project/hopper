package website

import (
	"context"
	"net/http"
)

func newLima() *lima { return &lima{} }

type lima struct{}

func (*lima) Name() string        { return "lima" }
func (*lima) Hostname() string    { return "github.com/lima-vm/lima" }
func (*lima) MonitorPage() string { return "https://github.com/lima-vm/lima/releases" }

func (*lima) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "lima-vm/lima")
}
