package website

import (
	"context"
	"net/http"
)

func newGpt4all() *gpt4all { return &gpt4all{} }

type gpt4all struct{}

func (*gpt4all) Name() string        { return "gpt4all" }
func (*gpt4all) Hostname() string    { return "nomic.ai" }
func (*gpt4all) MonitorPage() string { return "https://www.nomic.ai/gpt4all" }

func (*gpt4all) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "nomic-ai/gpt4all")
}
