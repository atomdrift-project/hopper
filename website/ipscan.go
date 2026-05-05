package website

import (
	"context"
	"net/http"
)

func newIPScan() *ipscan { return &ipscan{} }

type ipscan struct{}

func (*ipscan) Name() string        { return "angryipscanner" }
func (*ipscan) Hostname() string    { return "angryip.org" }
func (*ipscan) MonitorPage() string { return "https://angryip.org/download/" }

func (*ipscan) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "angryip/ipscan")
}
