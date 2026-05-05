package website

import (
	"context"
	"net/http"
)

func newPEBear() *pebear { return &pebear{} }

type pebear struct{}

func (*pebear) Name() string        { return "pebear" }
func (*pebear) Hostname() string    { return "github.com/hasherezade/pe-bear" }
func (*pebear) MonitorPage() string { return "https://github.com/hasherezade/pe-bear/releases" }

// PE-bear by hasherezade — PE file inspector for Windows malware analysts.
func (*pebear) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "hasherezade/pe-bear")
}
