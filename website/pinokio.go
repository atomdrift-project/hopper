package website

import (
	"context"
	"net/http"
)

func newPinokio() *pinokio { return &pinokio{} }

type pinokio struct{}

func (*pinokio) Name() string        { return "pinokio" }
func (*pinokio) Hostname() string    { return "pinokio.computer" }
func (*pinokio) MonitorPage() string { return "https://pinokio.computer/" }

func (*pinokio) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "pinokiocomputer/pinokio")
}
