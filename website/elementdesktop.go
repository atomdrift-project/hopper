package website

import (
	"context"
	"net/http"
)

func newElementdesktop() *elementdesktop { return &elementdesktop{} }

type elementdesktop struct{}

func (*elementdesktop) Name() string        { return "elementdesktop" }
func (*elementdesktop) Hostname() string    { return "element.io" }
func (*elementdesktop) MonitorPage() string { return "https://element.io/download" }

// // Element Matrix client desktop app.
func (*elementdesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "element-hq/element-desktop")
}
