package website

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// liveAPIResponse mirrors the shape of /api/product/info captured 2026-05.
// Two ONLINE variants (types 1 and 2) point at the same URL — exercise the
// dedupe path. Type 3 is the full offline installer; type 4 is the portable
// zip (the only artifact whose URL embeds the version string).
const liveAPIResponse = `{
  "product": {
    "MajorVersionNumber": 7,
    "MinorVersionNumber": 7,
    "BuildNumber": 1313,
    "ProductVariants": [
      {"Type": 1, "Url": "https://bits.avcdn.net/productfamily_CCLEANER7/insttype_FREE/platform_WIN/installertype_ONLINE/build_RELEASE"},
      {"Type": 2, "Url": "https://bits.avcdn.net/productfamily_CCLEANER7/insttype_FREE/platform_WIN/installertype_ONLINE/build_RELEASE"},
      {"Type": 3, "Url": "https://bits.avcdn.net/productfamily_CCLEANER7/insttype_FREE/platform_WIN/installertype_FULL/build_RELEASE"},
      {"Type": 4, "Url": "https://download.ccleaner.com/portable/ccsetup640.zip"}
    ]
  }
}`

func TestCCleanerDiscover(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		status   int
		wantURLs []string
		wantErr  string
	}{
		{
			name:   "live response shape",
			body:   liveAPIResponse,
			status: http.StatusOK,
			wantURLs: []string{
				"https://bits.avcdn.net/productfamily_CCLEANER7/insttype_FREE/platform_WIN/installertype_ONLINE/build_RELEASE",
				"https://bits.avcdn.net/productfamily_CCLEANER7/insttype_FREE/platform_WIN/installertype_FULL/build_RELEASE",
				"https://download.ccleaner.com/portable/ccsetup640.zip",
			},
		},
		{
			name:    "no variants",
			body:    `{"product":{"MajorVersionNumber":7,"MinorVersionNumber":7,"BuildNumber":1313,"ProductVariants":[]}}`,
			status:  http.StatusOK,
			wantErr: "no variants",
		},
		{
			name:    "non-200",
			body:    "Service Unavailable",
			status:  http.StatusServiceUnavailable,
			wantErr: "HTTP 503",
		},
		{
			name:    "malformed json",
			body:    `{"product":{`,
			status:  http.StatusOK,
			wantErr: "decode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/product/info" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				if got := r.URL.Query().Get("product"); got != "ccleaner" {
					t.Errorf("product query = %q, want ccleaner", got)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer srv.Close()

			c := &ccleaner{api: srv.URL + "/api/product/info?product=ccleaner&variant=free"}
			targets, err := c.Discover(context.Background(), srv.Client())

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Discover: want error containing %q, got nil (targets=%v)", tc.wantErr, targets)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Discover error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if len(targets) != len(tc.wantURLs) {
				t.Fatalf("got %d targets, want %d: %+v", len(targets), len(tc.wantURLs), targets)
			}
			for i, want := range tc.wantURLs {
				if targets[i].URL != want {
					t.Errorf("target[%d].URL = %q, want %q", i, targets[i].URL, want)
				}
				if targets[i].Variant == "" {
					t.Errorf("target[%d].Variant is empty", i)
				}
			}
		})
	}
}

func TestCCleanerVariantLabels(t *testing.T) {
	cases := map[int]string{
		1:  "windows-online-installer",
		2:  "windows-online-installer",
		3:  "windows-full-installer",
		4:  "windows-portable",
		99: "type-99",
	}
	for code, want := range cases {
		if got := ccleanerVariantLabel(code); got != want {
			t.Errorf("ccleanerVariantLabel(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestCCleanerInDefault(t *testing.T) {
	for _, s := range Default() {
		if s.Name() == "ccleaner" {
			if s.Hostname() != "ccleaner.com" {
				t.Errorf("Hostname = %q, want ccleaner.com", s.Hostname())
			}
			if !strings.HasPrefix(s.MonitorPage(), "https://www.ccleaner.com/") {
				t.Errorf("MonitorPage = %q, want www.ccleaner.com URL", s.MonitorPage())
			}
			return
		}
	}
	t.Fatal("ccleaner not in Default()")
}
