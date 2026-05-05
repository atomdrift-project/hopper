package website

import (
	"context"
	"net/http"
)

func newRustup() *rustup { return &rustup{} }

type rustup struct{}

func (*rustup) Name() string        { return "rustup" }
func (*rustup) Hostname() string    { return "rustup.rs" }
func (*rustup) MonitorPage() string { return "https://rustup.rs/" }

// Rustup ships a per-architecture stable URL for the bootstrap installer
// the user is told to download. The bytes behind each URL rotate when
// rustup itself releases. These are the URLs `rustup.rs` advertises in its
// "select your platform" dropdown.
var rustupArtifacts = []struct {
	arch string
	url  string
}{
	{"x86_64-pc-windows-msvc", "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"},
	{"i686-pc-windows-msvc", "https://static.rust-lang.org/rustup/dist/i686-pc-windows-msvc/rustup-init.exe"},
	{"aarch64-pc-windows-msvc", "https://static.rust-lang.org/rustup/dist/aarch64-pc-windows-msvc/rustup-init.exe"},
	{"x86_64-apple-darwin", "https://static.rust-lang.org/rustup/dist/x86_64-apple-darwin/rustup-init"},
	{"aarch64-apple-darwin", "https://static.rust-lang.org/rustup/dist/aarch64-apple-darwin/rustup-init"},
	{"x86_64-unknown-linux-gnu", "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"},
	{"aarch64-unknown-linux-gnu", "https://static.rust-lang.org/rustup/dist/aarch64-unknown-linux-gnu/rustup-init"},
}

func (*rustup) Discover(_ context.Context, _ *http.Client) ([]Target, error) {
	out := make([]Target, 0, len(rustupArtifacts))
	for _, a := range rustupArtifacts {
		out = append(out, Target{URL: a.url, Variant: a.arch})
	}
	return out, nil
}
