package website

import (
	"context"
	"net/http"
)

func newVagrant() *vagrant { return &vagrant{} }

type vagrant struct{}

func (*vagrant) Name() string        { return "vagrant" }
func (*vagrant) Hostname() string    { return "vagrantup.com" }
func (*vagrant) MonitorPage() string { return "https://www.vagrantup.com/downloads" }

func (*vagrant) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "hashicorp/vagrant")
}
