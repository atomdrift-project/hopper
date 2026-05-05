package website

import (
	"context"
	"net/http"
)

func newOBSStudio() *obsstudio { return &obsstudio{} }

type obsstudio struct{}

func (*obsstudio) Name() string        { return "obsstudio" }
func (*obsstudio) Hostname() string    { return "obsproject.com" }
func (*obsstudio) MonitorPage() string { return "https://obsproject.com/download" }

func (*obsstudio) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "obsproject/obs-studio")
}
