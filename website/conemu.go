package website

import (
	"context"
	"net/http"
)

func newConEmu() *conemu { return &conemu{} }

type conemu struct{}

func (*conemu) Name() string        { return "conemu" }
func (*conemu) Hostname() string    { return "conemu.github.io" }
func (*conemu) MonitorPage() string { return "https://conemu.github.io/" }

func (*conemu) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "ConEmu/ConEmu")
}
