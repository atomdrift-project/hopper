package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

func TestUploaderOf(t *testing.T) {
	t.Parallel()
	const browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15"
	for _, tc := range []struct {
		name, origin, agent string
		headers             map[string]string
		want                string
	}{
		{name: "origin wins over the relay's agent", origin: "poppy", agent: "atomdrift-scan/3.1.0", want: "poppy"},
		{name: "origin from postdoc's beamline caller", origin: "beamline", agent: "atomdrift-scan/3.1.0", want: "beamline"},
		{name: "origin wins over a browser", origin: "scan", agent: browser, want: "scan"},
		{name: "origin is sanitized as relays do", origin: " PoP_PY!\x00 ", agent: "postdoc/1", want: "poppy"},
		{name: "sanitized origin naming a client", origin: "WEB_SITE", agent: "postdoc/1", want: "website"},
		{name: "origin alias", origin: "atomdrift-scan", agent: "postdoc/1", want: "scan"},
		{name: "unknown origin", origin: "curl", agent: "atomdrift-scan/3.1.0", want: otherUploader},
		{name: "oversized origin is cut, then unknown", origin: "poppy" + strings.Repeat("x", 4096), agent: "postdoc/1", want: otherUploader},
		{name: "origin of nothing but junk falls back to the agent", origin: "!!! ~~~ \u00e9", agent: "postdoc/0.9.1", want: "postdoc"},
		{name: "postdoc worker", agent: "postdoc/0.9.1", want: "postdoc"},
		{name: "postdoc serve, through scan's client", agent: "atomdrift-scan/3.1.0", want: "scan"},
		{name: "scan", agent: "scan/3.1.0", want: "scan"},
		{name: "beamline", agent: "beamline/1", want: "beamline"},
		{name: "poppy", agent: "poppy/1 (+https://github.com/atomdrift-project/poppy)", want: "poppy"},
		{name: "prism", agent: "prism (atomdrift)", want: "website"},
		{name: "forager", agent: "atomdrift-supplychain-forager/1.1 (+mailto:x@example.test)", want: "forager"},
		{name: "browser", agent: browser, want: "website"},
		{name: "browser, lower case", agent: "mozilla/4.0", want: "website"},
		{name: "fetch metadata", agent: "something/1", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, want: "website"},
		{name: "origin header of a form post", agent: "something/1", headers: map[string]string{"Origin": "https://atomdrift.org"}, want: "website"},
		{name: "a known client sending fetch metadata", agent: "postdoc/1", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, want: "postdoc"},
		{name: "an unknown origin is not a browser", origin: "curl", agent: "something/1", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, want: otherUploader},
		{name: "product token ends at any space", agent: "poppy\t1", want: "poppy"},
		{name: "unknown agent", agent: "my-tool/2.0", want: otherUploader},
		{name: "agent with a comment only", agent: "my-tool (+https://example.test)", want: otherUploader},
		{name: "nothing", want: ""},
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/intake/upload", http.NoBody)
		if tc.origin != "" {
			r.Header.Set(originHeader, tc.origin)
		}
		if tc.agent != "" {
			r.Header.Set("User-Agent", tc.agent)
		}
		for k, v := range tc.headers {
			r.Header.Set(k, v)
		}
		if got := uploaderOf(r); got != tc.want {
			t.Errorf("%s: uploaderOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSanitizeOrigin(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"poppy":                  "poppy",
		"Poppy":                  "poppy",
		"a b/c_d":                "abcd",
		strings.Repeat("ab", 40): strings.Repeat("ab", 16),
		"\u00e9t\u00e9":          "t",
		"":                       "",
		"----":                   "----",
	} {
		if got := sanitizeOrigin(in); got != want {
			t.Errorf("sanitizeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSourceFeed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ source, feed, want string }{
		{"upload", "postdoc", "upload:postdoc"},
		{"upload", "website", "upload:website"},
		{"upload", "other", "upload:other"},
		{"upload", "", "upload"},
		// A producer's own feed, or an alias no row is stored under.
		{"upload", "aikido", "upload/aikido"},
		{"upload", "prism", "upload/prism"},
		// Only an upload has an uploader.
		{"walk", "postdoc", "walk/postdoc"},
		{"forager", "aikido", "forager/aikido"},
	} {
		if got := sourceFeed(tc.source, tc.feed); got != tc.want {
			t.Errorf("sourceFeed(%q, %q) = %q, want %q", tc.source, tc.feed, got, tc.want)
		}
	}
}

// The dashboard's lists show an upload as upload:<uploader>.
func TestDashboardShowsUploader(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	writeWorkflowSamples(&buf, "Latest", "", []hopper.WorkflowSample{
		{SHA256: strings.Repeat("a", 64), Source: "upload", Feed: "poppy", Filename: "a.tgz"},
		{SHA256: strings.Repeat("b", 64), Source: "forager", Feed: "aikido", Filename: "b.tgz"},
	}, "created")
	writeWorkflowBacklogs(&buf, []hopper.WorkflowBacklog{
		{Source: "upload", Feed: "website", PendingCleave: 3},
		{Source: "forager", Feed: "osv", PendingCleave: 4},
	})
	page := buf.String()
	for _, want := range []string{"<td>upload:poppy</td>", "<td>forager/aikido</td>", "<td>upload:website</td>", "<td>osv</td>"} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard lacks %s:\n%s", want, page)
		}
	}
}

// An upload is stored under the source "upload" with its uploader in the
// feed, in the legacy schema and in the verdict store; a producer's own feed
// is kept over it.
func TestUploadRecordsUploader(t *testing.T) {
	t.Parallel()
	post := func(api *apiServer, file []byte, headers map[string]string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/v1/intake/upload?filename=x.bin", bytes.NewReader(file))
		r.Header.Set("Content-Type", "application/octet-stream")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		api.handleUpload(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("upload: code %d body %s", w.Code, w.Body.String())
		}
		h := sha256.Sum256(file)
		return hex.EncodeToString(h[:])
	}

	t.Run("legacy schema", func(t *testing.T) {
		t.Parallel()
		api := uploadAPI(t)
		sha := post(api, []byte("bytes a browser sent"), map[string]string{"User-Agent": "Mozilla/5.0"})
		got, err := api.db.SampleBySHA256(t.Context(), sha)
		if err != nil {
			t.Fatal(err)
		}
		if got.Source != "upload" || got.LabelSource != "upload" || got.Feed != "website" {
			t.Errorf("source %q, label source %q, feed %q; want upload, upload, website", got.Source, got.LabelSource, got.Feed)
		}

		file := []byte("bytes forager fetched from npm")
		body, ct := multipartUpload(t, validProvenance(t, file, hexSum(file)), file, true)
		r := httptest.NewRequest(http.MethodPost, "/v1/intake/upload", body)
		r.Header.Set("Content-Type", ct)
		r.Header.Set("User-Agent", "atomdrift-supplychain-forager/1.1")
		w := httptest.NewRecorder()
		api.handleUpload(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("upload: code %d body %s", w.Code, w.Body.String())
		}
		if got, err := api.db.SampleBySHA256(t.Context(), hexSum(file)); err != nil || got.Feed != "npm" {
			t.Errorf("feed %q, %v; want the producer's own feed, npm", got.Feed, err)
		}
	})

	t.Run("verdict store", func(t *testing.T) {
		t.Parallel()
		api, st, _ := verdictAPI(t)
		api.dataRoot = t.TempDir()
		for _, tc := range []struct {
			file    string
			headers map[string]string
			want    string
		}{
			{"bytes poppy asked about", map[string]string{originHeader: "poppy", "User-Agent": "atomdrift-scan/3.1.0"}, "poppy"},
			{"bytes postdoc serve filed", map[string]string{"User-Agent": "atomdrift-scan/3.1.0"}, "scan"},
			{"bytes a stranger sent", map[string]string{originHeader: "evil-tool", "User-Agent": "atomdrift-scan/3.1.0"}, otherUploader},
		} {
			sha := post(api, []byte(tc.file), tc.headers)
			sum, err := hex.DecodeString(sha)
			if err != nil {
				t.Fatal(err)
			}
			got, err := st.Sample(t.Context(), sum)
			if err != nil || got.Location == nil {
				t.Fatalf("%s: sample %+v, %v", tc.file, got, err)
			}
			if got.Location.Source != "upload" || got.Location.Feed != tc.want {
				t.Errorf("%s: source %q, feed %q; want upload, %s", tc.file, got.Location.Source, got.Location.Feed, tc.want)
			}
		}
	})
}
