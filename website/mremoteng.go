package website

import (
	"context"
	"net/http"
)

func newMRemoteNG() *mremoteng { return &mremoteng{} }

type mremoteng struct{}

func (*mremoteng) Name() string        { return "mremoteng" }
func (*mremoteng) Hostname() string    { return "mremoteng.org" }
func (*mremoteng) MonitorPage() string { return "https://mremoteng.org/download" }

func (*mremoteng) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "mRemoteNG/mRemoteNG")
}
