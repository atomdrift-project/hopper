package website

import (
	"context"
	"net/http"
)

func newMpv() *mpv { return &mpv{} }

type mpv struct{}

func (*mpv) Name() string        { return "mpv" }
func (*mpv) Hostname() string    { return "mpv.io" }
func (*mpv) MonitorPage() string { return "https://mpv.io/installation/" }

func (*mpv) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "mpv-player/mpv")
}
