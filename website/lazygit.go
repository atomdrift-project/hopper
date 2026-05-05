package website

import (
	"context"
	"net/http"
)

func newLazygit() *lazygit { return &lazygit{} }

type lazygit struct{}

func (*lazygit) Name() string        { return "lazygit" }
func (*lazygit) Hostname() string    { return "github.com/jesseduffield/lazygit" }
func (*lazygit) MonitorPage() string { return "https://github.com/jesseduffield/lazygit/releases" }

func (*lazygit) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "jesseduffield/lazygit")
}
