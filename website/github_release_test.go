package website

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// expandedAssetsFixture mirrors the relevant subset of GitHub's
// /releases/expanded_assets/<tag> response: an HTML fragment with <a href>
// links to downloads. The real fragment also contains size and digest spans
// we don't need.
const expandedAssetsFixture = `<include-fragment>
<ul>
  <li><a href="/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/snapshot_2024-12-01.zip">snapshot_2024-12-01.zip</a></li>
  <li><a href="/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/snapshot_2024-12-01.zip">duplicate</a></li>
  <li><a href="/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/source.tar.gz">source.tar.gz</a></li>
  <li><a href="/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/notes.txt">notes.txt</a></li>
  <li><a href="/x64dbg/x64dbg/elsewhere">unrelated</a></li>
</ul>
</include-fragment>`

func newGithubFixture(t *testing.T, tag, fragment string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/x64dbg/x64dbg/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/x64dbg/x64dbg/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/x64dbg/x64dbg/releases/tag/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>tag page</body></html>")) //nolint:errcheck // test helper
	})
	mux.HandleFunc("/x64dbg/x64dbg/releases/expanded_assets/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fragment)) //nolint:errcheck // test helper
	})
	return httptest.NewServer(mux)
}

func TestGithubReleaseAssets(t *testing.T) {
	srv := newGithubFixture(t, "snapshot_2024-12-01", expandedAssetsFixture)
	defer srv.Close()

	targets, err := githubReleaseAssetsAt(context.Background(), srv.Client(), srv.URL, "x64dbg/x64dbg")
	if err != nil {
		t.Fatalf("githubReleaseAssetsAt: %v", err)
	}

	urls := make([]string, len(targets))
	for i, tgt := range targets {
		urls[i] = tgt.URL
	}
	sort.Strings(urls)

	want := []string{
		"https://github.com/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/notes.txt",
		"https://github.com/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/snapshot_2024-12-01.zip",
		"https://github.com/x64dbg/x64dbg/releases/download/snapshot_2024-12-01/source.tar.gz",
	}
	if len(urls) != len(want) {
		t.Fatalf("got %d targets, want %d:\ngot:  %v\nwant: %v", len(urls), len(want), urls, want)
	}
	for i, w := range want {
		if urls[i] != w {
			t.Errorf("[%d] = %q, want %q", i, urls[i], w)
		}
	}

	// Spot-check one variant — the .tar.gz compound extension must be
	// stripped as a unit.
	for _, tgt := range targets {
		if strings.HasSuffix(tgt.URL, "/source.tar.gz") && tgt.Variant != "source" {
			t.Errorf("source.tar.gz variant = %q, want %q", tgt.Variant, "source")
		}
		if strings.HasSuffix(tgt.URL, "/notes.txt") && tgt.Variant != "notes" {
			t.Errorf("notes.txt variant = %q, want %q", tgt.Variant, "notes")
		}
	}
}

func TestGithubReleaseAssetsErrors(t *testing.T) {
	tests := []struct {
		name string
		want string
		set  func(t *testing.T) *httptest.Server
	}{
		{
			name: "no fragment matches",
			want: "no assets in fragment",
			set: func(t *testing.T) *httptest.Server {
				t.Helper()
				return newGithubFixture(t, "v1", `<html><body>no asset hrefs here</body></html>`)
			},
		},
		{
			name: "404 on latest",
			want: "HTTP 404",
			set: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.NotFound(w, nil)
				}))
			},
		},
		{
			name: "bad repo format",
			want: "must be \"owner/name\"",
			set: func(t *testing.T) *httptest.Server {
				t.Helper()
				return httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.set(t)
			defer srv.Close()
			repo := "x64dbg/x64dbg"
			if tc.name == "bad repo format" {
				repo = "noslash"
			}
			_, err := githubReleaseAssetsAt(context.Background(), srv.Client(), srv.URL, repo)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestGithubReleaseVariant(t *testing.T) {
	cases := map[string]string{
		"snapshot_2024-12-01.zip": "snapshot_2024-12-01",
		"source.tar.gz":           "source",
		"linux-x64.tar.xz":        "linux-x64",
		"7zr.exe":                 "7zr",
		"binary-no-ext":           "binary-no-ext",
		"":                        "",
	}
	for in, want := range cases {
		if got := githubReleaseVariant(in); got != want {
			t.Errorf("githubReleaseVariant(%q) = %q, want %q", in, got, want)
		}
	}
}
