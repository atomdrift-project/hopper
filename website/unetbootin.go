package website

import (
	"context"
	"net/http"
)

func newUnetbootin() *unetbootin { return &unetbootin{} }

type unetbootin struct{}

func (*unetbootin) Name() string        { return "unetbootin" }
func (*unetbootin) Hostname() string    { return "unetbootin.github.io" }
func (*unetbootin) MonitorPage() string { return "https://unetbootin.github.io/" }

func (*unetbootin) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "unetbootin/unetbootin")
}
