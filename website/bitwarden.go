package website

import (
	"context"
	"net/http"
)

func newBitwarden() *bitwarden { return &bitwarden{} }

type bitwarden struct{}

func (*bitwarden) Name() string        { return "bitwarden" }
func (*bitwarden) Hostname() string    { return "bitwarden.com" }
func (*bitwarden) MonitorPage() string { return "https://bitwarden.com/download/" }

func (*bitwarden) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "bitwarden/clients")
}
