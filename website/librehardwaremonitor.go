package website

import (
	"context"
	"net/http"
)

func newLibreHardwareMonitor() *libreHardwareMonitor { return &libreHardwareMonitor{} }

type libreHardwareMonitor struct{}

func (*libreHardwareMonitor) Name() string     { return "librehardwaremonitor" }
func (*libreHardwareMonitor) Hostname() string { return "librehardwaremonitor.org" }
func (*libreHardwareMonitor) MonitorPage() string {
	return "https://github.com/LibreHardwareMonitor/LibreHardwareMonitor/releases"
}

// LibreHardwareMonitor publishes Windows installer + portable zip + .NET
// nupkgs per release. This is the modern fork of OpenHardwareMonitor and
// directly thematic to the hwmonitor supply-chain attack we're guarding
// against.
func (*libreHardwareMonitor) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "LibreHardwareMonitor/LibreHardwareMonitor")
}
