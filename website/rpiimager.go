package website

import (
	"context"
	"net/http"
)

func newRpiimager() *rpiimager { return &rpiimager{} }

type rpiimager struct{}

func (*rpiimager) Name() string        { return "rpiimager" }
func (*rpiimager) Hostname() string    { return "raspberrypi.com" }
func (*rpiimager) MonitorPage() string { return "https://www.raspberrypi.com/software/" }

func (*rpiimager) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "raspberrypi/rpi-imager")
}
