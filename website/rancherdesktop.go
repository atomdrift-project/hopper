package website

import (
	"context"
	"net/http"
)

func newRancherdesktop() *rancherdesktop { return &rancherdesktop{} }

type rancherdesktop struct{}

func (*rancherdesktop) Name() string        { return "rancherdesktop" }
func (*rancherdesktop) Hostname() string    { return "rancherdesktop.io" }
func (*rancherdesktop) MonitorPage() string { return "https://rancherdesktop.io/" }

func (*rancherdesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "rancher-sandbox/rancher-desktop")
}
