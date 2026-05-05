package website

import (
	"context"
	"net/http"
)

func newYara() *yara { return &yara{} }

type yara struct{}

func (*yara) Name() string        { return "yara" }
func (*yara) Hostname() string    { return "virustotal.github.io" }
func (*yara) MonitorPage() string { return "https://github.com/VirusTotal/yara/releases" }

// YARA — pattern-matching Swiss Army knife for malware classification.
func (*yara) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "VirusTotal/yara")
}
