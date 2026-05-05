package website

import (
	"context"
	"net/http"
)

func newJanai() *janai { return &janai{} }

type janai struct{}

func (*janai) Name() string        { return "janai" }
func (*janai) Hostname() string    { return "jan.ai" }
func (*janai) MonitorPage() string { return "https://jan.ai/" }

func (*janai) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "janhq/jan")
}
