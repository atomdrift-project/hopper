package website

import (
	"context"
	"net/http"
)

func newAudacity() *audacity { return &audacity{} }

type audacity struct{}

func (*audacity) Name() string        { return "audacity" }
func (*audacity) Hostname() string    { return "audacityteam.org" }
func (*audacity) MonitorPage() string { return "https://www.audacityteam.org/download/" }

func (*audacity) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "audacity/audacity")
}
