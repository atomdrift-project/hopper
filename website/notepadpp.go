package website

import (
	"context"
	"net/http"
)

func newNotepadPP() *notepadpp { return &notepadpp{} }

type notepadpp struct{}

func (*notepadpp) Name() string        { return "notepadpp" }
func (*notepadpp) Hostname() string    { return "notepad-plus-plus.org" }
func (*notepadpp) MonitorPage() string { return "https://notepad-plus-plus.org/downloads/" }

// Notepad++ links from notepad-plus-plus.org/downloads/v<ver>/ straight to
// its GitHub Releases. The vendor site is essentially a thin wrapper; the
// canonical artifacts live at notepad-plus-plus/notepad-plus-plus.
func (*notepadpp) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "notepad-plus-plus/notepad-plus-plus")
}
