package website

import (
	"context"
	"net/http"
)

func newColima() *colima { return &colima{} }

type colima struct{}

func (*colima) Name() string        { return "colima" }
func (*colima) Hostname() string    { return "github.com/abiosoft/colima" }
func (*colima) MonitorPage() string { return "https://github.com/abiosoft/colima/releases" }

func (*colima) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "abiosoft/colima")
}
