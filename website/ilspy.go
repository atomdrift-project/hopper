package website

import (
	"context"
	"net/http"
)

func newILSpy() *ilspy { return &ilspy{} }

type ilspy struct{}

func (*ilspy) Name() string        { return "ilspy" }
func (*ilspy) Hostname() string    { return "github.com/icsharpcode/ILSpy" }
func (*ilspy) MonitorPage() string { return "https://github.com/icsharpcode/ILSpy/releases" }

func (*ilspy) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "icsharpcode/ILSpy")
}
