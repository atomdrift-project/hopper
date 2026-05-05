package website

import (
	"context"
	"net/http"
)

func newMinikube() *minikube { return &minikube{} }

type minikube struct{}

func (*minikube) Name() string        { return "minikube" }
func (*minikube) Hostname() string    { return "minikube.sigs.k8s.io" }
func (*minikube) MonitorPage() string { return "https://minikube.sigs.k8s.io/docs/start/" }

func (*minikube) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "kubernetes/minikube")
}
