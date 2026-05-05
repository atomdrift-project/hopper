package website

import (
	"context"
	"net/http"
)

func newSystemInformer() *systemInformer { return &systemInformer{} }

type systemInformer struct{}

func (*systemInformer) Name() string        { return "systeminformer" }
func (*systemInformer) Hostname() string    { return "systeminformer.sourceforge.io" }
func (*systemInformer) MonitorPage() string { return "https://systeminformer.sourceforge.io/" }

// System Informer (formerly Process Hacker) — Windows process explorer used
// by sysadmins, malware analysts, and reverse engineers. Releases on GitHub
// at winsiderss/systeminformer.
func (*systemInformer) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "winsiderss/systeminformer")
}
