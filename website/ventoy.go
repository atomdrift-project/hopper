package website

import (
	"context"
	"net/http"
)

func newVentoy() *ventoy { return &ventoy{} }

type ventoy struct{}

func (*ventoy) Name() string        { return "ventoy" }
func (*ventoy) Hostname() string    { return "ventoy.net" }
func (*ventoy) MonitorPage() string { return "https://www.ventoy.net/en/download.html" }

// Ventoy releases the same artifact set (Windows installer, Linux tarball,
// LiveCD ISO) under a single tag like "v1.1.07" on GitHub.
func (*ventoy) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "ventoy/Ventoy")
}
