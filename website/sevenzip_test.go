package website

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// sevenZipFixtureHTML is a trimmed-down copy of www.7-zip.org/download.html
// containing both a current-version block and a legacy block, plus assorted
// noise (translation links, an outbound "7-max" link). The extractor must
// pick the current version and skip everything else.
const sevenZipFixtureHTML = `<!DOCTYPE HTML>
<HTML><HEAD><TITLE>Download</TITLE></HEAD>
<BODY>
<P><A href="https://7-max.com">7-max</A></P>
<H1>Download</H1>

<P><B>Download 7-Zip 26.01 (2026-04-27) for Windows</B>:</P>
<TABLE>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.exe">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601.exe">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-arm64.exe">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.msi">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-linux-x64.tar.xz">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-mac.tar.xz">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-src.7z">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/lzma2601.7z">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7zr.exe">Download</A></TD></TR>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.exe">Dup-link</A></TD></TR>
</TABLE>

<P><B>Download 7-Zip 24.09 (2024-11-29) for Windows</B>:</P>
<TABLE>
  <TR><TD><A href="https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.exe">Download</A></TD></TR>
  <TR><TD><A href="a/7z2301-x64.exe">Legacy</A></TD></TR>
</TABLE>
</BODY></HTML>`

func TestSevenZipDiscover(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		status      int
		wantURLs    []string
		wantVariant map[string]string // url-suffix → expected Variant
		wantErr     string
	}{
		{
			name:   "live shape",
			body:   sevenZipFixtureHTML,
			status: http.StatusOK,
			wantURLs: []string{
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-arm64.exe",
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-linux-x64.tar.xz",
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-mac.tar.xz",
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-src.7z",
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.exe",
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.msi",
				"https://github.com/ip7z/7zip/releases/download/26.01/7z2601.exe",
				"https://github.com/ip7z/7zip/releases/download/26.01/7zr.exe",
				"https://github.com/ip7z/7zip/releases/download/26.01/lzma2601.7z",
			},
			wantVariant: map[string]string{
				"7z2601-x64.exe":          "x64.exe",
				"7z2601.exe":              "x86.exe",
				"7z2601-arm64.exe":        "arm64.exe",
				"7z2601-x64.msi":          "x64.msi",
				"7z2601-linux-x64.tar.xz": "linux-x64.tar.xz",
				"7z2601-mac.tar.xz":       "mac.tar.xz",
				"7z2601-src.7z":           "src.7z",
				"lzma2601.7z":             "lzma.7z",
				"7zr.exe":                 "7zr.exe",
			},
		},
		{
			name:    "no current heading",
			body:    `<html><body><h1>Hello</h1></body></html>`,
			status:  http.StatusOK,
			wantErr: "current-version heading not found",
		},
		{
			name:    "heading present but no matching artifacts",
			body:    `<html><body><p><b>Download 7-Zip 99.99 (3000-01-01) for Windows</b></p><p>Coming soon</p></body></html>`,
			status:  http.StatusOK,
			wantErr: "no artifacts for version 99.99",
		},
		{
			name:    "non-200",
			body:    "Service Unavailable",
			status:  http.StatusServiceUnavailable,
			wantErr: "HTTP 503",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Errorf("write: %v", err)
				}
			}))
			defer srv.Close()

			s := &sevenZip{page: srv.URL + "/download.html"}
			targets, err := s.Discover(context.Background(), srv.Client())

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Discover: want error %q, got nil (targets=%v)", tc.wantErr, targets)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Discover error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}

			urls := make([]string, len(targets))
			for i, tgt := range targets {
				urls[i] = tgt.URL
			}
			sort.Strings(urls)
			if len(urls) != len(tc.wantURLs) {
				t.Fatalf("got %d targets, want %d:\ngot:  %v\nwant: %v", len(urls), len(tc.wantURLs), urls, tc.wantURLs)
			}
			for i, want := range tc.wantURLs {
				if urls[i] != want {
					t.Errorf("targets[%d] = %q, want %q", i, urls[i], want)
				}
			}

			for _, tgt := range targets {
				base := tgt.URL[strings.LastIndex(tgt.URL, "/")+1:]
				if want, ok := tc.wantVariant[base]; ok && tgt.Variant != want {
					t.Errorf("variant for %s = %q, want %q", base, tgt.Variant, want)
				}
			}
		})
	}
}

func TestSevenZipVariant(t *testing.T) {
	cases := []struct {
		href    string
		version string
		want    string
	}{
		{"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-x64.exe", "26.01", "x64.exe"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/7z2601.exe", "26.01", "x86.exe"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/7z2601.msi", "26.01", "x86.msi"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-arm64.exe", "26.01", "arm64.exe"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-linux-arm64.tar.xz", "26.01", "linux-arm64.tar.xz"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/7z2601-src.7z", "26.01", "src.7z"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/lzma2601.7z", "26.01", "lzma.7z"},
		{"https://github.com/ip7z/7zip/releases/download/26.01/7zr.exe", "26.01", "7zr.exe"},
		// Multi-digit version with dots: "9.20" → flat "920".
		{"https://github.com/ip7z/7zip/releases/download/9.20/7z920-x64.msi", "9.20", "x64.msi"},
	}
	for _, tc := range cases {
		if got := sevenZipVariant(tc.href, tc.version); got != tc.want {
			t.Errorf("sevenZipVariant(%q, %q) = %q, want %q", tc.href, tc.version, got, tc.want)
		}
	}
}

func TestSevenZipInDefault(t *testing.T) {
	for _, s := range Default() {
		if s.Name() == "7zip" {
			if s.Hostname() != "7-zip.org" {
				t.Errorf("Hostname = %q, want 7-zip.org", s.Hostname())
			}
			if !strings.HasPrefix(s.MonitorPage(), "https://www.7-zip.org/") {
				t.Errorf("MonitorPage = %q, want www.7-zip.org URL", s.MonitorPage())
			}
			return
		}
	}
	t.Fatal("7zip not in Default()")
}
