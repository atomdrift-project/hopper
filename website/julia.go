package website

import (
	"context"
	"net/http"
)

func newJulia() *julia { return &julia{} }

type julia struct{}

func (*julia) Name() string        { return "julia" }
func (*julia) Hostname() string    { return "julialang.org" }
func (*julia) MonitorPage() string { return "https://julialang.org/downloads/" }

func (*julia) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "JuliaLang/julia")
}
