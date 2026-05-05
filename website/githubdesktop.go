package website

import (
	"context"
	"net/http"
)

func newGithubdesktop() *githubdesktop { return &githubdesktop{} }

type githubdesktop struct{}

func (*githubdesktop) Name() string        { return "githubdesktop" }
func (*githubdesktop) Hostname() string    { return "desktop.github.com" }
func (*githubdesktop) MonitorPage() string { return "https://desktop.github.com/" }

func (*githubdesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "desktop/desktop")
}
