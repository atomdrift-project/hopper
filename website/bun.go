package website

import (
	"context"
	"net/http"
)

func newBun() *bun { return &bun{} }

type bun struct{}

func (*bun) Name() string        { return "bun" }
func (*bun) Hostname() string    { return "bun.sh" }
func (*bun) MonitorPage() string { return "https://bun.sh/" }

// Bun — JavaScript runtime / package manager. Releases tagged "bun-vX.Y.Z".
func (*bun) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "oven-sh/bun")
}
