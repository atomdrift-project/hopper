package website

import (
	"context"
	"net/http"
)

func newDnSpy() *dnspy { return &dnspy{} }

type dnspy struct{}

func (*dnspy) Name() string        { return "dnspyex" }
func (*dnspy) Hostname() string    { return "github.com/dnSpyEx/dnSpy" }
func (*dnspy) MonitorPage() string { return "https://github.com/dnSpyEx/dnSpy/releases" }

// dnSpyEx is the maintained fork of the abandoned-then-archived dnSpy
// .NET debugger / decompiler. Heavily used in Windows malware reversing.
func (*dnspy) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "dnSpyEx/dnSpy")
}
