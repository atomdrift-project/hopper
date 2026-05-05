package website

import (
	"context"
	"net/http"
)

func newHashcat() *hashcat { return &hashcat{} }

type hashcat struct{}

func (*hashcat) Name() string        { return "hashcat" }
func (*hashcat) Hostname() string    { return "hashcat.net" }
func (*hashcat) MonitorPage() string { return "https://hashcat.net/hashcat/" }

func (*hashcat) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "hashcat/hashcat")
}
