package website

import (
	"context"
	"net/http"
)

func newMultipass() *multipass { return &multipass{} }

type multipass struct{}

func (*multipass) Name() string        { return "multipass" }
func (*multipass) Hostname() string    { return "multipass.run" }
func (*multipass) MonitorPage() string { return "https://multipass.run/" }

func (*multipass) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "canonical/multipass")
}
