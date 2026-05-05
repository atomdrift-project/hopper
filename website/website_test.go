package website

import (
	"net/url"
	"strings"
	"testing"
)

// TestDefaultSourceIntegrity is a cheap structural check on every source the
// binary ships with: unique names, valid hostnames, monitor pages that parse
// as URLs. Failures here mean a new source was added with a typo before
// anyone tried to fetch it.
func TestDefaultSourceIntegrity(t *testing.T) {
	sources := Default()
	if len(sources) == 0 {
		t.Fatal("Default() returned no sources")
	}
	names := map[string]bool{}
	for _, s := range sources {
		name := s.Name()
		if name == "" {
			t.Errorf("empty Name() on source with hostname %q", s.Hostname())
		}
		if names[name] {
			t.Errorf("duplicate Name() %q", name)
		}
		names[name] = true

		// Hostname becomes a directory under fetched/. We allow nested
		// paths like "github.com/owner/repo" for github-native projects
		// that have no separate vendor domain — these still produce a
		// stable on-disk subtree. Reject only literal whitespace, ".."
		// (path-traversal), and absolute paths.
		h := s.Hostname()
		switch {
		case h == "":
			t.Errorf("source %q: empty Hostname()", name)
		case strings.Contains(h, " "):
			t.Errorf("source %q: Hostname() %q contains whitespace", name, h)
		case strings.Contains(h, ".."):
			t.Errorf("source %q: Hostname() %q contains \"..\"", name, h)
		case strings.HasPrefix(h, "/"):
			t.Errorf("source %q: Hostname() %q is absolute", name, h)
		}

		mp := s.MonitorPage()
		if mp == "" {
			t.Errorf("source %q: empty MonitorPage()", name)
			continue
		}
		u, err := url.Parse(mp)
		if err != nil {
			t.Errorf("source %q: MonitorPage parse: %v", name, err)
			continue
		}
		if u.Scheme != "https" {
			t.Errorf("source %q: MonitorPage %q is not https", name, mp)
		}
		if u.Host == "" {
			t.Errorf("source %q: MonitorPage %q has empty host", name, mp)
		}
	}
}
