package website

import (
	"context"
	"net/http"
)

func newTemurin17() *temurin17 { return &temurin17{} }

type temurin17 struct{}

func (*temurin17) Name() string        { return "temurin17" }
func (*temurin17) Hostname() string    { return "adoptium.net" }
func (*temurin17) MonitorPage() string { return "https://adoptium.net/temurin/releases/?version=17" }

func (*temurin17) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "adoptium/temurin17-binaries")
}
