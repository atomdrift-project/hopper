package website

import (
	"context"
	"net/http"
)

func newHelix() *helix { return &helix{} }

type helix struct{}

func (*helix) Name() string        { return "helix" }
func (*helix) Hostname() string    { return "helix-editor.com" }
func (*helix) MonitorPage() string { return "https://helix-editor.com/" }

func (*helix) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "helix-editor/helix")
}
