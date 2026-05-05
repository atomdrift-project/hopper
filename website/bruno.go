package website

import (
	"context"
	"net/http"
)

func newBruno() *bruno { return &bruno{} }

type bruno struct{}

func (*bruno) Name() string        { return "bruno" }
func (*bruno) Hostname() string    { return "usebruno.com" }
func (*bruno) MonitorPage() string { return "https://www.usebruno.com/downloads" }

func (*bruno) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "usebruno/bruno")
}
