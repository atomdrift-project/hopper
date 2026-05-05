package website

import (
	"context"
	"net/http"
)

func newFoundry() *foundry { return &foundry{} }

type foundry struct{}

func (*foundry) Name() string        { return "foundry" }
func (*foundry) Hostname() string    { return "getfoundry.sh" }
func (*foundry) MonitorPage() string { return "https://getfoundry.sh/" }

// Foundry — Ethereum/EVM development toolchain (forge, anvil, cast).
func (*foundry) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "foundry-rs/foundry")
}
