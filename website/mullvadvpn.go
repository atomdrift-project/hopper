package website

import (
	"context"
	"net/http"
)

func newMullvadvpn() *mullvadvpn { return &mullvadvpn{} }

type mullvadvpn struct{}

func (*mullvadvpn) Name() string        { return "mullvadvpn" }
func (*mullvadvpn) Hostname() string    { return "mullvad.net" }
func (*mullvadvpn) MonitorPage() string { return "https://mullvad.net/en/download" }

func (*mullvadvpn) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "mullvad/mullvadvpn-app")
}
