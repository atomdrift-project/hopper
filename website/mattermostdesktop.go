package website

import (
	"context"
	"net/http"
)

func newMattermostdesktop() *mattermostdesktop { return &mattermostdesktop{} }

type mattermostdesktop struct{}

func (*mattermostdesktop) Name() string        { return "mattermostdesktop" }
func (*mattermostdesktop) Hostname() string    { return "mattermost.com" }
func (*mattermostdesktop) MonitorPage() string { return "https://mattermost.com/apps/" }

func (*mattermostdesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "mattermost/desktop")
}
