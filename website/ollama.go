package website

import (
	"context"
	"net/http"
)

func newOllama() *ollama { return &ollama{} }

type ollama struct{}

func (*ollama) Name() string        { return "ollama" }
func (*ollama) Hostname() string    { return "ollama.com" }
func (*ollama) MonitorPage() string { return "https://ollama.com/download" }

// Ollama publishes mac and Windows installers at ollama.com/download/<file>
// (which 307-redirect to the current GitHub release) plus a Linux install
// script at ollama.com/install.sh. Monitoring the vendor-published URLs
// (rather than going directly to GitHub) is the right call: if ollama.com
// is compromised, the redirect targets or the install script change — that's
// the attack we want to catch. Linux binary tarballs are not hosted on
// ollama.com (the install script downloads them from GitHub directly), so
// we don't fetch them here.
var ollamaArtifacts = []struct {
	url     string
	variant string
}{
	{"https://ollama.com/download/Ollama.dmg", "macos"},
	{"https://ollama.com/download/Ollama-darwin.zip", "macos-zip"},
	{"https://ollama.com/download/OllamaSetup.exe", "windows"},
	{"https://ollama.com/install.sh", "linux-installer-script"},
}

func (*ollama) Discover(_ context.Context, _ *http.Client) ([]Target, error) {
	out := make([]Target, 0, len(ollamaArtifacts))
	for _, a := range ollamaArtifacts {
		out = append(out, Target{URL: a.url, Variant: a.variant})
	}
	return out, nil
}
