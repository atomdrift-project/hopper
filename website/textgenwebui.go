package website

import (
	"context"
	"net/http"
)

func newTextgenwebui() *textgenwebui { return &textgenwebui{} }

type textgenwebui struct{}

func (*textgenwebui) Name() string        { return "textgenwebui" }
func (*textgenwebui) Hostname() string    { return "github.com/oobabooga/textgen" }
func (*textgenwebui) MonitorPage() string { return "https://github.com/oobabooga/textgen/releases" }

func (*textgenwebui) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "oobabooga/textgen")
}
