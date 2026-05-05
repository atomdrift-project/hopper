package website

import (
	"context"
	"net/http"
)

func newDbeaver() *dbeaver { return &dbeaver{} }

type dbeaver struct{}

func (*dbeaver) Name() string        { return "dbeaver" }
func (*dbeaver) Hostname() string    { return "dbeaver.io" }
func (*dbeaver) MonitorPage() string { return "https://dbeaver.io/download/" }

func (*dbeaver) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "dbeaver/dbeaver")
}
