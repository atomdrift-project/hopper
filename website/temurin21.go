package website

import (
	"context"
	"net/http"
)

func newTemurin21() *temurin21 { return &temurin21{} }

type temurin21 struct{}

func (*temurin21) Name() string        { return "temurin21" }
func (*temurin21) Hostname() string    { return "adoptium.net" }
func (*temurin21) MonitorPage() string { return "https://adoptium.net/temurin/releases/?version=21" }

func (*temurin21) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "adoptium/temurin21-binaries")
}
