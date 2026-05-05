package website

import (
	"context"
	"net/http"
)

func newPeazip() *peazip { return &peazip{} }

type peazip struct{}

func (*peazip) Name() string        { return "peazip" }
func (*peazip) Hostname() string    { return "peazip.github.io" }
func (*peazip) MonitorPage() string { return "https://peazip.github.io/" }

func (*peazip) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "peazip/PeaZip")
}
