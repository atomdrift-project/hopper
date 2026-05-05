package website

import (
	"context"
	"net/http"
)

func newIperf3() *iperf3 { return &iperf3{} }

type iperf3 struct{}

func (*iperf3) Name() string        { return "iperf3" }
func (*iperf3) Hostname() string    { return "iperf.fr" }
func (*iperf3) MonitorPage() string { return "https://iperf.fr/iperf-download.php" }

// iperf3 source releases on GitHub. Windows binaries on iperf.fr come from
// a third-party builder; we monitor the upstream-source release here.
func (*iperf3) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "esnet/iperf")
}
