package website

import (
	"context"
	"net/http"
)

func newZaproxy() *zaproxy { return &zaproxy{} }

type zaproxy struct{}

func (*zaproxy) Name() string        { return "zaproxy" }
func (*zaproxy) Hostname() string    { return "zaproxy.org" }
func (*zaproxy) MonitorPage() string { return "https://www.zaproxy.org/download/" }

func (*zaproxy) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "zaproxy/zaproxy")
}
