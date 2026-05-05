package website

import (
	"context"
	"net/http"
)

func newHWMonitor() *hwmonitor { return &hwmonitor{} }

type hwmonitor struct{}

func (*hwmonitor) Name() string        { return "hwmonitor" }
func (*hwmonitor) Hostname() string    { return "cpuid.com/hwmonitor" }
func (*hwmonitor) MonitorPage() string { return "https://www.cpuid.com/softwares/hwmonitor.html" }

// HWMonitor (CPUID) — the supply-chain attack target that motivated this
// project. Distinct from HWiNFO. Setup .exe and .zip per release on a
// stable URL pattern at cpuid.com/downloads/hwmonitor/.
func (*hwmonitor) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return cpuidLatestAssets(ctx, hc, "hwmonitor")
}
