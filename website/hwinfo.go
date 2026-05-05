package website

import (
	"context"
	"net/http"
)

func newHWiNFO() *hwinfo { return &hwinfo{} }

type hwinfo struct{}

func (*hwinfo) Name() string        { return "hwinfo" }
func (*hwinfo) Hostname() string    { return "hwinfo.com" }
func (*hwinfo) MonitorPage() string { return "https://www.hwinfo.com/download/" }

// HWiNFO's vendor download page (and its dappcdn.com mirror) are gated by
// Cloudflare's managed challenge — a plain HTTP client cannot reach the
// install URLs. Discovery instead goes through Microsoft's winget-pkgs
// manifest repo, which publishes the same canonical installer URL on its
// non-Cloudflare CDN (sac.sk historically), plus a vendor-blessed SHA-256
// we can cross-check against once the engine wires that through.
func (*hwinfo) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return wingetInstallerURLs(ctx, hc, "REALiX.HWiNFO")
}
