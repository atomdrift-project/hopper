package website

import (
	"context"
	"net/http"
)

func newWinmerge() *winmerge { return &winmerge{} }

type winmerge struct{}

func (*winmerge) Name() string        { return "winmerge" }
func (*winmerge) Hostname() string    { return "winmerge.org" }
func (*winmerge) MonitorPage() string { return "https://winmerge.org/downloads/" }

func (*winmerge) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "WinMerge/winmerge")
}
