package website

import (
	"context"
	"net/http"
)

func newDeno() *deno { return &deno{} }

type deno struct{}

func (*deno) Name() string        { return "deno" }
func (*deno) Hostname() string    { return "deno.com" }
func (*deno) MonitorPage() string { return "https://deno.com/" }

func (*deno) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "denoland/deno")
}
