package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

// TestBrowse files the archive fixture under a release, as the walker and a
// worker would, and reads it back the way a frontend shows it.
func TestBrowse(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	pkg, script := digestOf("package bytes"), digestOf("script bytes")
	mtime := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	ingest(ctx, t, st, QueueNew, Arrival{
		SHA256: pkg, Size: 4000, Path: "good/npm/evil-1.0.0.tgz", Source: "walk", Feed: "npmjs.org",
		Name: "pkg:npm/evil", Version: "1.0.0", URL: "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz", Mtime: &mtime,
		Provenance: []byte(`{"artifact":{"filename":"evil-1.0.0.tgz"},"registry":{"record":{"title":"Evil","description":"does things","downloads_total":1234}}}`),
	})
	r.write(ctx, t, st)

	s, err := st.Sample(ctx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "pkg:npm/evil" || s.Version != "1.0.0" || s.Type != "npm" || s.Size != 4000 {
		t.Errorf("identity %q %q %q %d", s.Name, s.Version, s.Type, s.Size)
	}
	if s.Location == nil || s.Location.Path != "good/npm/evil-1.0.0.tgz" || s.Location.Feed != "npmjs.org" ||
		s.Location.Mtime == nil || !s.Location.Mtime.Equal(mtime) {
		t.Errorf("location %+v", s.Location)
	}
	if s.Scan == nil || s.Scan.Ruleset != "r1" || s.Scan.Engine != "3.0.0" || !s.Scan.Flagged {
		t.Errorf("scan %+v, want the fixture's, flagged for triage", s.Scan)
	}
	atom := s.Opinions["atomscan"]
	if atom.Class != "hostile" || atom.FiresAt == nil || *atom.FiresAt != 12 || !bytes.Contains(atom.Summary, []byte("fetches and runs")) {
		t.Errorf("atomscan %+v %s", atom, atom.Summary)
	}
	if ml := s.Opinions["ml"]; ml.Class != "benign" || !bytes.Contains(ml.Summary, []byte(`"prob"`)) {
		t.Errorf("ml %+v %s", ml, ml.Summary)
	}
	if s.Opinions["floor"].Class != "hostile" || len(s.Opinions) != 3 {
		t.Errorf("opinions %v, want atomscan, floor and ml", s.Opinions)
	}
	if !bytes.Contains(s.Provenance, []byte("evil-1.0.0.tgz")) {
		t.Errorf("provenance %s", s.Provenance)
	}
	if _, err := st.Sample(ctx, digestOf("never seen")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown bytes: %v, want ErrNotFound", err)
	}

	members, truncated, err := st.Members(ctx, s.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(members) != 1 || !bytes.Equal(members[0].SHA256, script) || members[0].Path != "package/install.js" ||
		members[0].Depth != 1 || members[0].Parent != s.ID || members[0].Type != "javascript" {
		t.Fatalf("members %+v truncated %v", members, truncated)
	}
	reports, err := st.Reports(ctx, []int64{s.ID, members[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if string(reports[s.ID]) != r.reports[0] || string(reports[members[0].ID]) != r.reports[1] {
		t.Errorf("reports %q and %q, want each as uploaded", reports[s.ID], reports[members[0].ID])
	}

	parents, err := st.Parents(ctx, script, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(parents) != 1 || parents[0].ID != s.ID || parents[0].Path != "package/install.js" || parents[0].Class != "hostile" ||
		parents[0].Filename != "evil-1.0.0.tgz" || parents[0].ScannedAt.IsZero() || parents[0].Location == nil {
		t.Errorf("parents %+v", parents)
	}

	rows, err := st.Feed(ctx, &FeedQuery{TopLevel: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("feed %+v, want the package alone: its member was never scanned on its own", rows)
	}
	f := rows[0]
	if f.Name != "pkg:npm/evil" || f.Class != "hostile" || f.Filename != "evil-1.0.0.tgz" || f.Feed != "npmjs.org" ||
		f.RegistryTitle != "Evil" || f.RegistryDescription != "does things" || f.RegistryDownloads != 1234 ||
		f.MLProb == nil || *f.MLProb != 0.05 || len(f.Top) != 1 || f.Reason == "" || f.ScannedAt.IsZero() {
		t.Errorf("feed row %+v", f)
	}
	if got := EcosystemOf(f.Name, f.Type); got != "javascript" {
		t.Errorf("ecosystem %q, want javascript", got)
	}

	if err := st.FileReport(ctx, TriageReport{Type: "re", Provider: "test", Content: "it is bad", SHA256: pkg}); err != nil {
		t.Fatal(err)
	}
	rep, err := st.LatestReport(ctx, pkg, "re")
	if err != nil || rep.Content != "it is bad" || rep.Provider != "test" {
		t.Errorf("report %+v %v", rep, err)
	}
	if _, err := st.LatestReport(ctx, pkg, "llm"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no report of that type: %v, want ErrNotFound", err)
	}
}

// TestFeedFilters checks each of the feed's filters against files judged one
// by one.
func TestFeedFilters(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	judge(ctx, t, st, "hostile npm", "hostile", 3, nil, nil)
	judge(ctx, t, st, "benign npm", "benign", -1, nil, nil)
	judge(ctx, t, st, "suspicious exe", "suspicious", 400, nil, nil)
	judge(ctx, t, st, "member", "hostile", 5, nil, nil)
	judge(ctx, t, st, "holder", "hostile", 5, []string{"member"}, nil)
	release(ctx, t, st, "hostile npm", "pkg:npm/bad", "1.0.0", "")
	release(ctx, t, st, "benign npm", "pkg:npm/good", "2.0.0", "")
	if _, err := st.pool.Exec(ctx, `UPDATE samples SET file_type = 'pe' WHERE sha256 = $1`, digestOf("suspicious exe")); err != nil {
		t.Fatal(err)
	}
	cite := Sighting{Source: "feed", Operator: "feed", Subject: hexOf(digestOf("hostile npm")), Claim: "malicious", Basis: "reviewed"}
	if _, err := st.AddSightings(ctx, []Sighting{cite}); err != nil {
		t.Fatal(err)
	}

	names := func(q FeedQuery) []string {
		t.Helper()
		q.Limit = cmpOr(q.Limit, 100)
		rows, err := st.Feed(ctx, &q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			for _, b := range []string{"hostile npm", "benign npm", "suspicious exe", "member", "holder"} {
				if bytes.Equal(r.SHA256, digestOf(b)) {
					out = append(out, b)
				}
			}
		}
		return out
	}
	all := []string{"holder", "member", "suspicious exe", "benign npm", "hostile npm"}
	hourAgo, inAnHour := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for _, c := range []struct {
		name string
		q    FeedQuery
		want []string
	}{
		{"everything, newest first", FeedQuery{}, all},
		{"top level leaves the member out", FeedQuery{TopLevel: true}, []string{"holder", "suspicious exe", "benign npm", "hostile npm"}},
		{"by class", FeedQuery{TopLevel: true, Classes: []string{"hostile"}}, []string{"holder", "hostile npm"}},
		{"two classes", FeedQuery{Classes: []string{"benign", "suspicious"}}, []string{"suspicious exe", "benign npm"}},
		// judge files everything as type npm, so a file with no name is
		// javascript by its type.
		{"by ecosystem", FeedQuery{Ecosystem: "javascript"}, []string{"holder", "member", "benign npm", "hostile npm"}},
		{"by ecosystem of the file type", FeedQuery{Ecosystem: "windows"}, []string{"suspicious exe"}},
		{"by name", FeedQuery{Name: "pkg:npm/bad"}, []string{"hostile npm"}},
		{"by release", FeedQuery{Name: "pkg:npm/good", Version: "2.0.0"}, []string{"benign npm"}},
		{"by names", FeedQuery{Names: []string{"pkg:npm/good", "pkg:npm/bad"}}, []string{"benign npm", "hostile npm"}},
		{"by digest", FeedQuery{Search: hexOf(digestOf("member"))}, []string{"member"}},
		{"by a substring of the path", FeedQuery{Search: "POOL/BENIGN"}, []string{"benign npm"}},
		{"cited", FeedQuery{Cited: true}, []string{"hostile npm"}},
		{"a page", FeedQuery{TopLevel: true, Limit: 2, Offset: 1}, []string{"suspicious exe", "benign npm"}},
		{"a window that has nothing", FeedQuery{Until: time.Now().Add(-time.Hour)}, nil},
		{"a window that has everything", FeedQuery{Since: hourAgo, Until: inAnHour}, all},
	} {
		if got := names(c.q); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	// The fixtures were scanned on 2026-11-12.
	ecosystems, feeds, err := st.Facets(ctx, time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ecosystems, []string{"javascript", "windows"}) || len(feeds) != 0 {
		t.Errorf("ecosystems %q, feeds %q", ecosystems, feeds)
	}
	if ecosystems, _, err := st.Facets(ctx, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)); err != nil || len(ecosystems) != 0 {
		t.Errorf("ecosystems scanned since: %q %v, want none", ecosystems, err)
	}

	named, err := st.Named(ctx, []string{"pkg:npm/bad", "pkg:npm/nothing"})
	if err != nil || !slices.Equal(named, []string{"pkg:npm/bad"}) {
		t.Errorf("named %q %v", named, err)
	}
	n, maxID, err := st.Count(ctx, 0)
	if err != nil || n != 5 || maxID == 0 {
		t.Errorf("count %d, max id %d, %v", n, maxID, err)
	}
	if more, top, err := st.Count(ctx, maxID); err != nil || more != 0 || top != maxID {
		t.Errorf("count after the top: %d, %d, %v", more, top, err)
	}
}

// TestFeedClaims finds a file by the identity it claims, inside its archive.
func TestFeedClaims(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.files[1]["ident"] = json.RawMessage(`{"name":{"value":"installer"},"signer":{"organization":"Evil Corp"}}`)
	r.write(ctx, t, st)
	rows, err := st.Feed(ctx, &FeedQuery{ClaimSigner: "Evil Corp", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !bytes.Equal(rows[0].SHA256, digestOf("script bytes")) {
		t.Fatalf("feed by signer %+v, want the member that claims it", rows)
	}
	s, err := st.Sample(ctx, digestOf("script bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Scan != nil || !bytes.Contains(s.Ident, []byte("Evil Corp")) {
		t.Errorf("member: scan %+v ident %s, want no scan of its own and its claim", s.Scan, s.Ident)
	}
}

func cmpOr(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}
