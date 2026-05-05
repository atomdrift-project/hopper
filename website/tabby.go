package website

import (
	"context"
	"net/http"
)

func newTabby() *tabby { return &tabby{} }

type tabby struct{}

func (*tabby) Name() string        { return "tabby" }
func (*tabby) Hostname() string    { return "tabby.sh" }
func (*tabby) MonitorPage() string { return "https://tabby.sh/" }

func (*tabby) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "Eugeny/tabby")
}
