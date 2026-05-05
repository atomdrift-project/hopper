package website

import (
	"context"
	"net/http"
)

func newHandBrake() *handbrake { return &handbrake{} }

type handbrake struct{}

func (*handbrake) Name() string        { return "handbrake" }
func (*handbrake) Hostname() string    { return "handbrake.fr" }
func (*handbrake) MonitorPage() string { return "https://handbrake.fr/downloads.php" }

func (*handbrake) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "HandBrake/HandBrake")
}
