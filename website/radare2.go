package website

import (
	"context"
	"net/http"
)

func newRadare2() *radare2 { return &radare2{} }

type radare2 struct{}

func (*radare2) Name() string        { return "radare2" }
func (*radare2) Hostname() string    { return "rada.re" }
func (*radare2) MonitorPage() string { return "https://rada.re/" }

func (*radare2) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "radareorg/radare2")
}
