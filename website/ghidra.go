package website

import (
	"context"
	"net/http"
)

func newGhidra() *ghidra { return &ghidra{} }

type ghidra struct{}

func (*ghidra) Name() string     { return "ghidra" }
func (*ghidra) Hostname() string { return "ghidra-sre.org" }
func (*ghidra) MonitorPage() string {
	return "https://github.com/NationalSecurityAgency/ghidra/releases/latest"
}

// Ghidra is published by NSA on GitHub Releases under tags like
// "Ghidra_12.0.4_build". The release ships a single big zip per platform
// plus checksums. We monitor under the project's identity (ghidra-sre.org)
// rather than github.com.
func (*ghidra) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "NationalSecurityAgency/ghidra")
}
