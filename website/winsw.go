package website

import (
	"context"
	"net/http"
)

func newWinSW() *winsw { return &winsw{} }

type winsw struct{}

func (*winsw) Name() string        { return "winsw" }
func (*winsw) Hostname() string    { return "github.com/winsw/winsw" }
func (*winsw) MonitorPage() string { return "https://github.com/winsw/winsw/releases" }

func (*winsw) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "winsw/winsw")
}
