package website

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// wingetTreeFixtureHTML mirrors the relevant subset of GitHub's tree page:
// an embedded JSON payload listing version subdirectories. The real page is
// ~300 KB; this fixture is just the minimum needed to exercise the regex.
const wingetTreeFixtureHTML = `<html><body>
<script type="application/json" data-target="react-app.embeddedData">
{"payload":{"tree":{"items":[
{"name":"8.34","path":"manifests/r/REALiX/HWiNFO/8.34","contentType":"directory"},
{"name":"8.40","path":"manifests/r/REALiX/HWiNFO/8.40","contentType":"directory"},
{"name":"8.42","path":"manifests/r/REALiX/HWiNFO/8.42","contentType":"directory"},
{"name":"8.44","path":"manifests/r/REALiX/HWiNFO/8.44","contentType":"directory"},
{"name":"8.46","path":"manifests/r/REALiX/HWiNFO/8.46","contentType":"directory"},
{"name":".validation.json","path":"manifests/r/REALiX/HWiNFO/.validation.json","contentType":"file"}
]}}}
</script>
</body></html>`

const wingetHWiNFOInstallerYAML = `# Created with YamlCreate.ps1 Dumplings Mod
PackageIdentifier: REALiX.HWiNFO
PackageVersion: "8.46"
InstallerType: inno
Installers:
- Architecture: x64
  InstallerUrl: https://www.sac.sk/download/utildiag/hwi_846x.exe
  InstallerSha256: 4D03CD106830642BDC4FEF1D5F9282F2420D96D3187A892C46F9AA104F5DB2FA
- Architecture: arm64
  InstallerUrl: https://www.sac.sk/download/utildiag/hwi_846x.exe
  InstallerSha256: 4D03CD106830642BDC4FEF1D5F9282F2420D96D3187A892C46F9AA104F5DB2FA
ManifestType: installer
ManifestVersion: 1.12.0
`

func TestWingetInstallerURLs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/tree/manifests/r/REALiX/HWiNFO", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(wingetTreeFixtureHTML)) //nolint:errcheck // test handler
	})
	mux.HandleFunc("/raw/manifests/r/REALiX/HWiNFO/8.46/REALiX.HWiNFO.installer.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(wingetHWiNFOInstallerYAML)) //nolint:errcheck // test handler
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	treeBase := srv.URL + "/tree/manifests"
	rawBase := srv.URL + "/raw/manifests"

	targets, err := wingetInstallerURLsAt(context.Background(), srv.Client(), treeBase, rawBase, "REALiX.HWiNFO")
	if err != nil {
		t.Fatalf("wingetInstallerURLsAt: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1: %+v", len(targets), targets)
	}
	want := "https://www.sac.sk/download/utildiag/hwi_846x.exe"
	if targets[0].URL != want {
		t.Errorf("URL = %q, want %q", targets[0].URL, want)
	}
	if targets[0].Variant == "" {
		t.Error("Variant must not be empty")
	}
}

func TestWingetInstallerURLsErrors(t *testing.T) {
	tests := []struct {
		name      string
		packageID string
		treeHTML  string
		manifest  string
		want      string
	}{
		{"bad packageID", "noseparator", "", "", "must be \"Publisher.Name\""},
		{
			name:      "no version directories",
			packageID: "REALiX.HWiNFO",
			treeHTML:  `<html><body><script type="application/json">{"payload":{"tree":{"items":[]}}}</script></body></html>`,
			want:      "no version directories",
		},
		{
			name:      "unparseable versions",
			packageID: "REALiX.HWiNFO",
			treeHTML: `<html><body><script type="application/json">{"payload":{"tree":{"items":[
{"name":"latest","path":"manifests/r/REALiX/HWiNFO/latest","contentType":"directory"}]}}}</script></body></html>`,
			want: "no parseable version",
		},
		{
			name:      "manifest no installers",
			packageID: "REALiX.HWiNFO",
			treeHTML: `<html><body><script type="application/json">{"payload":{"tree":{"items":[
{"name":"1.0","path":"manifests/r/REALiX/HWiNFO/1.0","contentType":"directory"}]}}}</script></body></html>`,
			manifest: `PackageIdentifier: REALiX.HWiNFO
PackageVersion: "1.0"
Installers: []
`,
			want: "no installers",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/tree/manifests/r/REALiX/HWiNFO", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				body := tc.treeHTML
				if body == "" {
					body = `<html></html>`
				}
				_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
			})
			if tc.manifest != "" {
				mux.HandleFunc("/raw/manifests/r/REALiX/HWiNFO/1.0/REALiX.HWiNFO.installer.yaml", func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(tc.manifest)) //nolint:errcheck // test handler
				})
			}
			srv := httptest.NewServer(mux)
			defer srv.Close()
			_, err := wingetInstallerURLsAt(context.Background(), srv.Client(),
				srv.URL+"/tree/manifests", srv.URL+"/raw/manifests", tc.packageID)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// Regression: GitHub's tree-page HTML also embeds the parent and root tree
// items for sidebar navigation. The version-listing regex must filter on the
// path prefix or it picks up sibling directories ("manifests/9", "manifests/z",
// "fonts", ".github", …) and confidently returns one as the "latest version".
func TestWingetListVersionsIgnoresSiblingTrees(t *testing.T) {
	const html = `<html><body>
<script type="application/json">
{"payload":{"tree":{"items":[
{"name":"8.42","path":"manifests/r/REALiX/HWiNFO/8.42","contentType":"directory"},
{"name":"8.46","path":"manifests/r/REALiX/HWiNFO/8.46","contentType":"directory"},
{"name":"9","path":"manifests/9","contentType":"directory"},
{"name":"z","path":"manifests/z","contentType":"directory"},
{"name":".github","path":".github","contentType":"directory"},
{"name":"fonts","path":"fonts","contentType":"directory"},
{"name":"Tools","path":"Tools","contentType":"directory"}
]}}}
</script>
</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(html)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	versions, err := wingetListVersions(context.Background(), srv.Client(), srv.URL, "r", "REALiX", "HWiNFO")
	if err != nil {
		t.Fatalf("wingetListVersions: %v", err)
	}
	want := []string{"8.42", "8.46"}
	if len(versions) != len(want) {
		t.Fatalf("got %v, want %v", versions, want)
	}
	for i, v := range want {
		if versions[i] != v {
			t.Errorf("[%d] = %q, want %q", i, versions[i], v)
		}
	}
}

func TestPickLatestVersion(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"8.34", "8.40", "8.42", "8.44", "8.46"}, "8.46"},
		{[]string{"1.9", "1.10", "1.2"}, "1.10"},
		{[]string{"v1.0.0", "v1.0.1", "v0.9"}, "v1.0.1"},
		{[]string{"1.2.3.4", "1.2.3"}, "1.2.3.4"},
		{[]string{"latest", "rolling"}, ""},
		{[]string{}, ""},
	}
	for _, tc := range cases {
		got := pickLatestVersion(tc.in)
		if got != tc.want {
			t.Errorf("pickLatestVersion(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseDottedInts(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		parts []int
	}{
		{"8.46", true, []int{8, 46}},
		{"v1.2.3", true, []int{1, 2, 3}},
		{"1", true, []int{1}},
		{"", false, nil},
		{"1.x.2", false, nil},
		{"1..2", false, nil},
	}
	for _, tc := range cases {
		parts, ok := parseDottedInts(tc.in)
		if ok != tc.ok {
			t.Errorf("parseDottedInts(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && fmt.Sprintf("%v", parts) != fmt.Sprintf("%v", tc.parts) {
			t.Errorf("parseDottedInts(%q) = %v, want %v", tc.in, parts, tc.parts)
		}
	}
}

func TestPickLatestVersionBeatsLex(t *testing.T) {
	xs := []string{"1.10", "1.9", "1.2"}
	sort.Strings(xs)
	if xs[len(xs)-1] != "1.9" {
		t.Skip("lex sort changed; test premise no longer holds")
	}
	got := pickLatestVersion([]string{"1.10", "1.9", "1.2"})
	if got != "1.10" {
		t.Errorf("pickLatestVersion lex-evaded test: got %q, want %q", got, "1.10")
	}
}
