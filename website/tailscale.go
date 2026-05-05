package website

import (
	"context"
	"net/http"
)

func newTailscale() *tailscale { return &tailscale{} }

type tailscale struct{}

func (*tailscale) Name() string        { return "tailscale" }
func (*tailscale) Hostname() string    { return "tailscale.com" }
func (*tailscale) MonitorPage() string { return "https://tailscale.com/download/" }

// Tailscale publishes per-OS installers under pkgs.tailscale.com/stable/ with
// stable filenames whose contents rotate as new releases ship. Linux clients
// install via apt/yum from the same host, so we don't fetch those — those
// downloads belong in a package-manager-monitor workstream.
var tailscaleArtifacts = []struct {
	url     string
	variant string
}{
	{"https://pkgs.tailscale.com/stable/Tailscale-latest-macos.pkg", "macos"},
	{"https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe", "windows"},
}

func (*tailscale) Discover(_ context.Context, _ *http.Client) ([]Target, error) {
	out := make([]Target, 0, len(tailscaleArtifacts))
	for _, a := range tailscaleArtifacts {
		out = append(out, Target{URL: a.url, Variant: a.variant})
	}
	return out, nil
}
