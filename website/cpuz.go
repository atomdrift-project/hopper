package website

import (
	"context"
	"net/http"
)

func newCPUZ() *cpuz { return &cpuz{} }

type cpuz struct{}

func (*cpuz) Name() string        { return "cpuz" }
func (*cpuz) Hostname() string    { return "cpuid.com/cpu-z" }
func (*cpuz) MonitorPage() string { return "https://www.cpuid.com/softwares/cpu-z.html" }

// CPU-Z (CPUID) — system information utility. The download page lists the
// English and Chinese builds plus partner-branded editions (ROG, Aorus,
// MSI Gaming, etc.). Each is a separately-published binary worth tracking
// since attackers historically have impersonated the partner editions.
func (*cpuz) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return cpuidLatestAssets(ctx, hc, "cpu-z")
}
