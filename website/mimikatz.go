package website

import (
	"context"
	"net/http"
)

func newMimikatz() *mimikatz { return &mimikatz{} }

type mimikatz struct{}

func (*mimikatz) Name() string        { return "mimikatz" }
func (*mimikatz) Hostname() string    { return "github.com/gentilkiwi/mimikatz" }
func (*mimikatz) MonitorPage() string { return "https://github.com/gentilkiwi/mimikatz/releases" }

func (*mimikatz) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "gentilkiwi/mimikatz")
}
