package website

import (
	"context"
	"net/http"
)

func newRufus() *rufus { return &rufus{} }

type rufus struct{}

func (*rufus) Name() string        { return "rufus" }
func (*rufus) Hostname() string    { return "rufus.ie" }
func (*rufus) MonitorPage() string { return "https://rufus.ie/en/" }

// Rufus is hosted at rufus.ie but the download page links straight to GitHub
// Releases (pbatard/rufus). We monitor the upstream identity (rufus.ie) but
// discover via GitHub.
//
// Note: Rufus also publishes BETA releases as separate GitHub releases that
// /releases/latest does not surface (they're flagged prerelease). Tracking
// betas would require a second pass; deferred until we have a need.
func (*rufus) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "pbatard/rufus")
}
