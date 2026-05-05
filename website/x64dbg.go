package website

import (
	"context"
	"net/http"
)

func newX64dbg() *x64dbg { return &x64dbg{} }

type x64dbg struct{}

func (*x64dbg) Name() string        { return "x64dbg" }
func (*x64dbg) Hostname() string    { return "x64dbg.com" }
func (*x64dbg) MonitorPage() string { return "https://x64dbg.com/" }

// Discovery delegates to the shared GitHub helper. x64dbg ships continuous
// snapshots tagged like "snapshot_2024-12-01"; "/releases/latest" tracks the
// most recent snapshot.
func (*x64dbg) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "x64dbg/x64dbg")
}
