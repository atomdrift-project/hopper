package hopper

import (
	"context"
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
