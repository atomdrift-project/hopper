package website

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

const wiresharkFixture = `<html><body>
<h5>Stable Release: 4.6.5</h5>
<a href="https://2.na.dl.wireshark.org/win64/Wireshark-4.6.5-x64.exe">Win x64</a>
<a href="https://2.na.dl.wireshark.org/win64/Wireshark-4.6.5-arm64.exe">Win arm64</a>
<a href="https://2.na.dl.wireshark.org/win64/WiresharkPortable64_4.6.5.paf.exe">Portable</a>
<a href="https://2.na.dl.wireshark.org/osx/Wireshark%204.6.5.dmg">macOS</a>
<a href="https://2.na.dl.wireshark.org/src/wireshark-4.6.5.tar.xz">Source</a>
<a href="https://2.na.dl.wireshark.org/win64/Wireshark-4.6.5-x64.exe">Dup</a>

<h5>Old Stable Release: 4.4.15</h5>
<a href="https://2.na.dl.wireshark.org/win64/Wireshark-4.4.15-x64.exe">Old Win</a>
<a href="https://2.na.dl.wireshark.org/src/wireshark-4.4.15.tar.xz">Old src</a>

<a href="https://npcap.com/">Npcap</a>
</body></html>`

func TestWiresharkDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(wiresharkFixture)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	s := &wireshark{page: srv.URL + "/download.html"}
	targets, err := s.Discover(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	urls := make([]string, len(targets))
	for i, tgt := range targets {
		urls[i] = tgt.URL
	}
	sort.Strings(urls)
	want := []string{
		"https://2.na.dl.wireshark.org/osx/Wireshark%204.6.5.dmg",
		"https://2.na.dl.wireshark.org/src/wireshark-4.6.5.tar.xz",
		"https://2.na.dl.wireshark.org/win64/Wireshark-4.6.5-arm64.exe",
		"https://2.na.dl.wireshark.org/win64/Wireshark-4.6.5-x64.exe",
		"https://2.na.dl.wireshark.org/win64/WiresharkPortable64_4.6.5.paf.exe",
	}
	if len(urls) != len(want) {
		t.Fatalf("got %d targets, want %d:\ngot:  %v\nwant: %v", len(urls), len(want), urls, want)
	}
	for i, w := range want {
		if urls[i] != w {
			t.Errorf("[%d] = %q, want %q", i, urls[i], w)
		}
	}

	for _, tgt := range targets {
		if strings.Contains(tgt.URL, "4.4.15") {
			t.Errorf("legacy URL leaked into targets: %q", tgt.URL)
		}
		if !strings.Contains(tgt.URL, "4.6.5") {
			t.Errorf("non-current URL: %q", tgt.URL)
		}
	}
}

func TestWiresharkDiscoverErrors(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{"no stable heading", "<html>nothing</html>", http.StatusOK, "stable-release heading not found"},
		{"heading present, no matching urls", `<html><h5>Stable Release: 99.99</h5><a href="https://2.na.dl.wireshark.org/win64/Wireshark-1.0-x64.exe">old</a></html>`, http.StatusOK, "no artifacts for stable 99.99"},
		{"non-200", "down", http.StatusServiceUnavailable, "HTTP 503"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body)) //nolint:errcheck // test handler
			}))
			defer srv.Close()
			s := &wireshark{page: srv.URL + "/x"}
			_, err := s.Discover(context.Background(), srv.Client())
			if err == nil {
				t.Fatalf("want error %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestWiresharkVariant(t *testing.T) {
	cases := map[string]string{
		"https://2.na.dl.wireshark.org/win64/Wireshark-4.6.5-x64.exe": "win64",
		"https://2.na.dl.wireshark.org/osx/Wireshark%204.6.5.dmg":     "osx",
		"https://2.na.dl.wireshark.org/src/wireshark-4.6.5.tar.xz":    "src",
	}
	for in, want := range cases {
		if got := wiresharkVariant(in); got != want {
			t.Errorf("wiresharkVariant(%q) = %q, want %q", in, got, want)
		}
	}
}
