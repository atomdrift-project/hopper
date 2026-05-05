package website

import (
	"context"
	"net/http"
)

func newTelegramdesktop() *telegramdesktop { return &telegramdesktop{} }

type telegramdesktop struct{}

func (*telegramdesktop) Name() string        { return "telegramdesktop" }
func (*telegramdesktop) Hostname() string    { return "telegram.org" }
func (*telegramdesktop) MonitorPage() string { return "https://telegram.org/apps" }

func (*telegramdesktop) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "telegramdesktop/tdesktop")
}
