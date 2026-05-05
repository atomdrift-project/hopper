package website

import (
	"context"
	"net/http"
)

func newRizin() *rizin { return &rizin{} }

type rizin struct{}

func (*rizin) Name() string        { return "rizin" }
func (*rizin) Hostname() string    { return "rizin.re" }
func (*rizin) MonitorPage() string { return "https://rizin.re/" }

func (*rizin) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "rizinorg/rizin")
}
