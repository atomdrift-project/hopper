package website

import (
	"context"
	"net/http"
)

func newKhoj() *khoj { return &khoj{} }

type khoj struct{}

func (*khoj) Name() string        { return "khoj" }
func (*khoj) Hostname() string    { return "khoj.dev" }
func (*khoj) MonitorPage() string { return "https://khoj.dev/" }

func (*khoj) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "khoj-ai/khoj")
}
