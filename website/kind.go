package website

import (
	"context"
	"net/http"
)

func newKind() *kind { return &kind{} }

type kind struct{}

func (*kind) Name() string        { return "kind" }
func (*kind) Hostname() string    { return "kind.sigs.k8s.io" }
func (*kind) MonitorPage() string { return "https://kind.sigs.k8s.io/" }

func (*kind) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "kubernetes-sigs/kind")
}
