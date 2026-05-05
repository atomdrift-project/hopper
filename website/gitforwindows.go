package website

import (
	"context"
	"net/http"
)

func newGitforwindows() *gitforwindows { return &gitforwindows{} }

type gitforwindows struct{}

func (*gitforwindows) Name() string        { return "gitforwindows" }
func (*gitforwindows) Hostname() string    { return "gitforwindows.org" }
func (*gitforwindows) MonitorPage() string { return "https://gitforwindows.org/" }

func (*gitforwindows) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "git-for-windows/git")
}
