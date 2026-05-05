package website

import (
	"context"
	"net/http"
)

func newAmass() *amass { return &amass{} }

type amass struct{}

func (*amass) Name() string        { return "amass" }
func (*amass) Hostname() string    { return "owasp-amass.github.io" }
func (*amass) MonitorPage() string { return "https://owasp-amass.github.io/" }

func (*amass) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "owasp-amass/amass")
}
