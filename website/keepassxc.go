package website

import (
	"context"
	"net/http"
)

func newKeePassXC() *keepassXC { return &keepassXC{} }

type keepassXC struct{}

func (*keepassXC) Name() string        { return "keepassxc" }
func (*keepassXC) Hostname() string    { return "keepassxc.org" }
func (*keepassXC) MonitorPage() string { return "https://keepassxc.org/download/" }

// KeePassXC's download page is a thin wrapper that links straight to GitHub
// Releases at keepassxreboot/keepassxc.
func (*keepassXC) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "keepassxreboot/keepassxc")
}
