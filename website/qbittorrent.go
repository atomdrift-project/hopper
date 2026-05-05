package website

import (
	"context"
	"net/http"
)

func newQbittorrent() *qbittorrent { return &qbittorrent{} }

type qbittorrent struct{}

func (*qbittorrent) Name() string        { return "qbittorrent" }
func (*qbittorrent) Hostname() string    { return "qbittorrent.org" }
func (*qbittorrent) MonitorPage() string { return "https://www.qbittorrent.org/download" }

func (*qbittorrent) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "qbittorrent/qBittorrent")
}
