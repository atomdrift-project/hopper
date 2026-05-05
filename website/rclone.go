package website

import (
	"context"
	"net/http"
)

func newRclone() *rclone { return &rclone{} }

type rclone struct{}

func (*rclone) Name() string        { return "rclone" }
func (*rclone) Hostname() string    { return "rclone.org" }
func (*rclone) MonitorPage() string { return "https://rclone.org/downloads/" }

func (*rclone) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "rclone/rclone")
}
