package website

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

const nssmFixtureHTML = `<html><body>
<p>2017-04-26: Users of Windows 10 Creators Update or newer should use
<a href="/ci/nssm-2.24-101-g897c7ad.zip">prelease build 2.24-101</a>
or any <a href="/builds">newer build</a> to avoid an issue with services.</p>

<h4>Latest release</h4>
<a href="/release/nssm-2.24.zip">nssm 2.24</a> <em>(2014-08-31)</em>

<h4>Featured pre-release</h4>
<a href="/ci/nssm-2.24-101-g897c7ad.zip">nssm 2.24-101-g897c7ad</a>

<a href="http://git.nssm.cc/nssm/nssm">git</a>
<a href="/release/nssm-2.24.zip">duplicate</a>
</body></html>`

func TestNSSMDiscover(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		status   int
		wantURLs []string
		wantErr  string
	}{
		{
			name:   "live shape",
			body:   nssmFixtureHTML,
			status: http.StatusOK,
			wantURLs: []string{
				"/ci/nssm-2.24-101-g897c7ad.zip",
				"/release/nssm-2.24.zip",
			},
		},
		{
			name:    "no asset links",
			body:    `<html><body><h4>Latest release</h4><p>Coming soon</p></body></html>`,
			status:  http.StatusOK,
			wantErr: "no NSSM zip links found",
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
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Errorf("write: %v", err)
				}
			}))
			defer srv.Close()

			s := &nssm{page: srv.URL + "/download"}
			targets, err := s.Discover(context.Background(), srv.Client())
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}

			paths := make([]string, len(targets))
			for i, tgt := range targets {
				// Strip the test-server prefix to make assertions stable.
				paths[i] = strings.TrimPrefix(tgt.URL, srv.URL)
			}
			sort.Strings(paths)
			if len(paths) != len(tc.wantURLs) {
				t.Fatalf("got %d targets, want %d:\ngot:  %v\nwant: %v", len(paths), len(tc.wantURLs), paths, tc.wantURLs)
			}
			for i, w := range tc.wantURLs {
				if paths[i] != w {
					t.Errorf("[%d] = %q, want %q", i, paths[i], w)
				}
			}

			// Variant labels: release vs prerelease.
			var sawRelease, sawPrerelease bool
			for _, tgt := range targets {
				switch tgt.Variant {
				case "release":
					sawRelease = true
				case "prerelease":
					sawPrerelease = true
				default:
					t.Errorf("unexpected variant %q", tgt.Variant)
				}
			}
			if !sawRelease || !sawPrerelease {
				t.Errorf("variants not both present: release=%v prerelease=%v", sawRelease, sawPrerelease)
			}
		})
	}
}
