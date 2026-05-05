package website

import (
	"context"
	"net/http"
)

func newFrida() *frida { return &frida{} }

type frida struct{}

func (*frida) Name() string        { return "frida" }
func (*frida) Hostname() string    { return "frida.re" }
func (*frida) MonitorPage() string { return "https://frida.re/" }

// Frida — dynamic instrumentation toolkit; the Windows/macOS/Linux server
// binaries plus per-arch tools live on the GitHub release.
func (*frida) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "frida/frida")
}
