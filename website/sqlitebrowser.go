package website

import (
	"context"
	"net/http"
)

func newSQLiteBrowser() *sqlitebrowser { return &sqlitebrowser{} }

type sqlitebrowser struct{}

func (*sqlitebrowser) Name() string        { return "sqlitebrowser" }
func (*sqlitebrowser) Hostname() string    { return "sqlitebrowser.org" }
func (*sqlitebrowser) MonitorPage() string { return "https://sqlitebrowser.org/dl/" }

func (*sqlitebrowser) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "sqlitebrowser/sqlitebrowser")
}
