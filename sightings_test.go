package hopper

import (
	"context"
	"strings"
	"testing"
)

// mustSample inserts a minimal analyzed top-level sample so the feed query and
// corroborated-flag maintenance have a row to match.
func mustCorroborationSample(t *testing.T, ctx context.Context, db *DB, sha, purlBase string) {
	t.Helper()
	mustInsert(t, ctx, db, &Sample{
		SHA256:      sha,
		Source:      "forager",
		Label:       "bad",
		LabelSource: "forager",
		PURLBase:    purlBase,
		Path:        "bad/" + sha,
		SizeBytes:   1,
	})
	mustAnalyze(t, ctx, db, sha, 100)
}

func TestAddSightingsIdempotentAndFlags(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mustCorroborationSample(t, ctx, db, sha, "pkg:npm/evil")

	// First write: one sighting by sha, one by version-less purl. Both are new.
	changed, err := db.AddSightings(ctx, []Sighting{
		{Source: "socket", Subject: sha, URL: "https://socket.dev/x", Note: "malware"},
		{Source: "aikido", Subject: "pkg:npm/evil", Note: "malware"},
	})
	if err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if changed != 2 {
		t.Fatalf("first AddSightings changed = %d, want 2", changed)
	}

	// Re-pushing the identical snapshot changes nothing (delta guard).
	changed, err = db.AddSightings(ctx, []Sighting{
		{Source: "socket", Subject: sha, URL: "https://socket.dev/x", Note: "malware"},
		{Source: "aikido", Subject: "pkg:npm/evil", Note: "malware"},
	})
	if err != nil {
		t.Fatalf("AddSightings re-push: %v", err)
	}
	if changed != 0 {
		t.Fatalf("re-push changed = %d, want 0", changed)
	}

	// Changing the note counts as a change.
	changed, err = db.AddSightings(ctx, []Sighting{
		{Source: "aikido", Subject: "pkg:npm/evil", Note: "protestware"},
	})
	if err != nil {
		t.Fatalf("AddSightings update: %v", err)
	}
	if changed != 1 {
		t.Fatalf("note change changed = %d, want 1", changed)
	}

	// SightingsFor returns both, grouped by subject.
	m, err := db.SightingsFor(ctx, []string{sha, "pkg:npm/evil"})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(m[sha]) != 1 || m[sha][0].Source != "socket" {
		t.Fatalf("sightings for sha = %+v, want one socket row", m[sha])
	}
	if len(m["pkg:npm/evil"]) != 1 || m["pkg:npm/evil"][0].Note != "protestware" {
		t.Fatalf("sightings for purl = %+v, want one aikido row noted protestware", m["pkg:npm/evil"])
	}
}

func TestSightingsCorroboratedFeedFilter(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const cited = "1111111111111111111111111111111111111111111111111111111111111111"
	const uncited = "2222222222222222222222222222222222222222222222222222222222222222"
	mustCorroborationSample(t, ctx, db, cited, "pkg:npm/one")
	mustCorroborationSample(t, ctx, db, uncited, "pkg:npm/two")

	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "osv", Subject: cited, Note: "MAL-2024-1"},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	// Unfiltered feed returns both; corroborated flag is set only on the cited one.
	all, err := db.FeedSamples(ctx, &FeedQuery{Source: "forager", TopLevelOnly: true, Limit: 10})
	if err != nil {
		t.Fatalf("FeedSamples: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered feed = %d rows, want 2", len(all))
	}
	for _, s := range all {
		want := s.SHA256 == cited
		if s.Corroborated != want {
			t.Fatalf("sample %s corroborated = %v, want %v", s.SHA256, s.Corroborated, want)
		}
	}

	// Corroborated-only filter returns just the cited sample.
	only, err := db.FeedSamples(ctx, &FeedQuery{Source: "forager", TopLevelOnly: true, Corroborated: true, Limit: 10})
	if err != nil {
		t.Fatalf("FeedSamples corroborated: %v", err)
	}
	if len(only) != 1 || only[0].SHA256 != cited {
		t.Fatalf("corroborated feed = %+v, want just %s", only, cited)
	}

	n, err := db.FeedSamplesCount(ctx, &FeedQuery{Source: "forager", TopLevelOnly: true, Corroborated: true})
	if err != nil {
		t.Fatalf("FeedSamplesCount: %v", err)
	}
	if n != 1 {
		t.Fatalf("corroborated count = %d, want 1", n)
	}
}

func TestSHACitedUnknowns(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	sha1 := strings.Repeat("1", 64)
	sha2 := strings.Repeat("2", 64)
	purlOnly := strings.Repeat("3", 64)
	outside := strings.Repeat("4", 64)
	for sha, path := range map[string]string{
		sha1:     "incoming/forager/npm/one.tgz",
		sha2:     "incoming/forager/npm/two.tgz",
		purlOnly: "incoming/forager/npm/three.tgz",
		outside:  "pending/forager/npm/four.tgz",
	} {
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "forager", Label: labelUnknown,
			LabelSource: "forager", Path: path, PURLBase: "pkg:npm/" + sha[:4],
		})
	}
	if _, err := db.AddSightings(ctx, []Sighting{
		{Source: "socket", Subject: sha1},
		{Source: "socket", Subject: sha2},
		{Source: "socket", Subject: "pkg:npm/" + purlOnly[:4]},
		{Source: "socket", Subject: outside},
	}); err != nil {
		t.Fatalf("AddSightings: %v", err)
	}

	page, err := db.SHACitedUnknowns(ctx, "incoming/", "", 1)
	if err != nil {
		t.Fatalf("SHACitedUnknowns page 1: %v", err)
	}
	if len(page) != 1 || page[0].SHA256 != sha1 || page[0].Path != "incoming/forager/npm/one.tgz" {
		t.Fatalf("page 1 = %+v, want %s at its exact path", page, sha1)
	}
	page, err = db.SHACitedUnknowns(ctx, "incoming/", page[0].SHA256, 10)
	if err != nil {
		t.Fatalf("SHACitedUnknowns page 2: %v", err)
	}
	if len(page) != 1 || page[0].SHA256 != sha2 {
		t.Fatalf("page 2 = %+v, want only %s", page, sha2)
	}
}

// TestAddSightingsNormalizesSubjects: the ledger keys corroboration by exact
// match, so subjects must land in canonical form no matter what spelling the
// producer holds — uppercase hashes lowercase, PURLs fold onto the canonical
// version-less purl_base.
func TestAddSightingsNormalizesSubjects(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	upperSHA := strings.ToUpper(strings.Repeat("ab", 32))
	n, err := db.AddSightings(ctx, []Sighting{
		{Source: "blog", Subject: upperSHA},
		{Source: "socket", Subject: "PKG:NPM/evil-pkg@1.2.3"}, // case + version drift
	})
	if err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if n != 2 {
		t.Fatalf("AddSightings changed %d, want 2", n)
	}

	got, err := db.SightingsFor(ctx, []string{strings.ToLower(upperSHA), "pkg:npm/evil-pkg"})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(got[strings.ToLower(upperSHA)]) != 1 {
		t.Errorf("uppercase sha not stored lowercase: %v", got)
	}
	if len(got["pkg:npm/evil-pkg"]) != 1 {
		t.Errorf("purl not stored as canonical version-less base: %v", got)
	}
}

// TestAddSightingsDedupesBatch: a batch may repeat a (source, subject) pair —
// two versions of one package share a purl_base, and normalization can
// collapse distinct spellings onto one subject. The upsert must not be handed
// the same row twice (Postgres rejects it, SQLSTATE 21000).
func TestAddSightingsDedupesBatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	n, err := db.AddSightings(ctx, []Sighting{
		{Source: "aikido", Subject: "pkg:npm/evil-pkg", URL: "https://a/1"},
		{Source: "aikido", Subject: "pkg:npm/evil-pkg", URL: "https://a/2"}, // same pair, other version's row
		{Source: "aikido", Subject: "pkg:npm/evil-pkg@2.0"},                 // normalizes onto the same pair
		{Source: "socket", Subject: "pkg:npm/evil-pkg"},                     // distinct source survives
	})
	if err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if n == 0 {
		t.Fatal("AddSightings changed 0, want > 0")
	}
	got, err := db.SightingsFor(ctx, []string{"pkg:npm/evil-pkg"})
	if err != nil {
		t.Fatalf("SightingsFor: %v", err)
	}
	if len(got["pkg:npm/evil-pkg"]) != 2 {
		t.Errorf("expected 2 sightings (one per source), got %v", got)
	}
}

func TestSightingFamily(t *testing.T) {
	tests := []struct{ source, want string }{
		{"ghsa", "github-advisories"},
		{"supplychain", "github-advisories"},
		{"osv", "ossf-malpkgs"},
		{"ossf", "ossf-malpkgs"},
		{"socket", "socket"}, // its own family
		{"aikido", "aikido"}, // kept separate from ossf despite overlap
		{"clamav", "clamav"}, // promoter's own detection is independent evidence
		{"cyclotron:https://example.com/feed", "cyclotron:https://example.com/feed"},
	}
	for _, tt := range tests {
		if got := SightingFamily(tt.source); got != tt.want {
			t.Errorf("SightingFamily(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}
	// The 2-independent-family rule collapses same-upstream pairs to one vote.
	if SightingFamily("ghsa") != SightingFamily("supplychain") {
		t.Error("ghsa and supplychain must share a family")
	}
	if SightingFamily("ghsa") == SightingFamily("socket") {
		t.Error("ghsa and socket must be independent families")
	}
}

func TestAddSightingsSkipsInvalid(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	changed, err := db.AddSightings(ctx, []Sighting{
		{Source: "", Subject: "pkg:npm/x"},               // no source
		{Source: "aikido", Subject: ""},                  // no subject
		{Source: "aikido", Subject: "not-a-sha-or-purl"}, // neither sha nor purl
	})
	if err != nil {
		t.Fatalf("AddSightings: %v", err)
	}
	if changed != 0 {
		t.Fatalf("changed = %d, want 0 (all invalid)", changed)
	}
}
