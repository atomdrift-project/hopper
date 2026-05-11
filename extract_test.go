package hopper

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"
)

func TestPathInsideArchive(t *testing.T) {
	cases := map[string]string{
		"archive.tgz!!package/index.js": "package/index.js",
		"a.zip!!b.zip!!inner.txt":       "inner.txt", // last separator wins
		"plain/path/no/separator":       "",
		"":                              "",
		"!!leading":                     "leading",
	}
	for in, want := range cases {
		if got := PathInsideArchive(in); got != want {
			t.Errorf("PathInsideArchive(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArchivePathMatches(t *testing.T) {
	tests := []struct {
		header, want string
		match        bool
	}{
		{"package/index.js", "package/index.js", true},
		{"package/index.js", "index.js", true}, // one level stripped
		{"./README.md", "README.md", true},
		{"a/b/c.txt", "b/c.txt", true},
		{"a/b/c.txt", "c.txt", false}, // only one level stripped
		{"index.js", "index.js", true},
		{"index.js", "package/index.js", false},
	}
	for _, tc := range tests {
		if got := archivePathMatches(tc.header, tc.want); got != tc.match {
			t.Errorf("archivePathMatches(%q, %q) = %v, want %v", tc.header, tc.want, got, tc.match)
		}
	}
}

func TestExtractFromArchiveTarGz(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	contents := map[string]string{
		"package/index.js":   "console.log('hi');\n",
		"package/inner/a.go": "package main\n",
	}
	for name, body := range contents {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	got, err := ExtractFromArchive(buf.Bytes(), "tar.gz", "index.js", 1<<20)
	if err != nil {
		t.Fatalf("extract index.js: %v", err)
	}
	if string(got) != contents["package/index.js"] {
		t.Errorf("index.js body = %q, want %q", got, contents["package/index.js"])
	}

	if _, err := ExtractFromArchive(buf.Bytes(), "tar.gz", "missing.txt", 1<<20); err == nil {
		t.Error("expected not-found error for missing path")
	}
}

func TestExtractFromArchiveZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("foo/bar.json")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(`{"name":"bar"}`)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	got, err := ExtractFromArchive(buf.Bytes(), "zip", "bar.json", 1<<20)
	if err != nil {
		t.Fatalf("extract bar.json: %v", err)
	}
	if string(got) != `{"name":"bar"}` {
		t.Errorf("got %q", got)
	}

	if _, err := ExtractFromArchive(buf.Bytes(), "whl", "missing", 1<<20); err == nil {
		t.Error("expected not-found error for missing path (zip-family)")
	}
}

func TestExtractFromArchiveUnsupported(t *testing.T) {
	if _, err := ExtractFromArchive([]byte("xx"), "rar", "x", 1024); err == nil {
		t.Error("expected unsupported-archive error for rar")
	}
}

func TestExtractFromArchiveTooLarge(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("big.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("A"), 1024)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	if _, err := ExtractFromArchive(buf.Bytes(), "zip", "big.txt", 100); err == nil {
		t.Error("expected too-large error when entry exceeds maxBytes")
	}
}
