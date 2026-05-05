package website

import (
	"context"
	"net/http"
)

func newProtonvpnwin() *protonvpnwin { return &protonvpnwin{} }

type protonvpnwin struct{}

func (*protonvpnwin) Name() string        { return "protonvpnwin" }
func (*protonvpnwin) Hostname() string    { return "protonvpn.com" }
func (*protonvpnwin) MonitorPage() string { return "https://protonvpn.com/download" }

func (*protonvpnwin) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "ProtonVPN/win-app")
}
