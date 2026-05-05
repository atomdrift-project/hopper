package website

import (
	"context"
	"net/http"
)

func newPodmandesktop() *podmandesktop { return &podmandesktop{} }

type podmandesktop struct{}

func (*podmandesktop) Name() string        { return "podmandesktop" }
func (*podmandesktop) Hostname() string    { return "podman-desktop.io" }
func (*podmandesktop) MonitorPage() string { return "https://podman-desktop.io/" }

func (*podmandesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "podman-desktop/podman-desktop")
}
