package hopper

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Sample is one struct, but three different statements write it: the singular
// upsert (InsertSample -> insertSampleNew{PG,SQLite}), the SQLite batch loop,
// and the Postgres staging COPY. Each spells its own column list by hand, and
// they drifted -- analyzed_at/first_analyzed_at were carried only by the batch
// paths, purl_base only by the singular one. A caller setting either field got
// it persisted or silently dropped depending on which exported method it
// reached, with no error either way. That cost an afternoon on 2026-09-01: a
// test fixture set AnalyzedAt, got a NULL column, and the queue predicate that
// reads it selected nothing.
//
// hopper already shares the hard half of this -- sampleConflictUpdatePG is used
// by both upserts "so their resolution logic can't drift" -- but the column
// lists stayed duplicated. This asserts the property that matters at the call
// site rather than comparing the lists: a field set on Sample survives whichever
// entry point the caller uses.
// TestMemberUpsertPreservesUnchangedToastPointers pins the CASE guards in
// memberConflictUpdatePG. A bare `cleave_result = EXCLUDED.cleave_result` reads
// as the obvious simplification, and it is the more expensive statement in the
// whole system: cleave_result is JSONB averaging 6.6 KB with 62% of rows over
// the TOAST threshold, so assigning EXCLUDED's fresh datum re-TOASTs the value
// even when the bytes are identical. Measured 2026-09-05, that made this one
// statement 73.7% of all master WAL (990 GB) and left the logical replica ~7.5 h
// behind. Assigning `samples.<col>` back preserves the original external TOAST
// pointer, which heap_update keeps instead of writing new chunks.
//
// The guards are semantically transparent — verified against the full
// stored/excluded NULL truth table — so only the write cost changes.
func TestMemberUpsertPreservesUnchangedToastPointers(t *testing.T) {
	for _, col := range []string{"cleave_result", "litmus_result"} {
		// The ELSE branch must hand back the STORED datum, not EXCLUDED's copy.
		if !strings.Contains(memberConflictUpdatePG, "ELSE samples."+col) {
			t.Errorf("memberConflictUpdatePG must fall back to samples.%s to preserve "+
				"the existing TOAST pointer; a bare EXCLUDED assignment re-TOASTs "+
				"an unchanged %s and was 73.7%% of master WAL", col, col)
		}
		if !strings.Contains(memberConflictUpdatePG, "samples."+col+" IS DISTINCT FROM EXCLUDED."+col) {
			t.Errorf("memberConflictUpdatePG must compare samples.%s against EXCLUDED.%s "+
				"so an unchanged value is not rewritten", col, col)
		}
	}
	// The timestamp refresh is the point of the statement and must stay
	// unconditional — skipping it would strand rescan scheduling on a stale
	// analyzed_at, which is a correctness change, not an optimization.
	if !strings.Contains(memberConflictUpdatePG, "analyzed_at = EXCLUDED.analyzed_at") {
		t.Error("memberConflictUpdatePG must still refresh analyzed_at unconditionally")
	}
}

func TestInsertPathsAgreeOnPersistedFields(t *testing.T) {
	ctx := context.Background()
	analyzed := time.Now().UTC().Truncate(time.Second)
	const sampleTopTraits = `[{"id":"objectives/impact/ransom","crit":5}]`

	sample := func(sha string) *Sample {
		return &Sample{
			SHA256: sha, Source: "test", Label: "good", LabelSource: "test",
			Path: "incoming/" + sha + ".tgz", FileType: "elf",
			PURLBase:      "pkg:npm/example",
			TraitsVersion: "abc12",
			TopTraits:     sampleTopTraits,
			AnalyzedAt:    &analyzed,
		}
	}

	// A sighting that PREDATES the sample, which is the ordinary case: forager
	// fetches a package a feed already named. The corroborate trigger fires on
	// sightings inserts only, so if a write path does not seed the flag itself
	// nothing ever will.
	seedSighting := func(t *testing.T, db *DB, subject string) {
		t.Helper()
		if _, err := db.AddSightings(ctx, []Sighting{{Source: "feed-a", Subject: subject}}); err != nil {
			t.Fatalf("AddSightings: %v", err)
		}
	}

	for _, tc := range []struct {
		name   string
		insert func(*DB, *Sample) error
	}{
		{"InsertSample", func(db *DB, s *Sample) error { return db.InsertSample(ctx, s) }},
		{"InsertSampleBatch", func(db *DB, s *Sample) error {
			_, _, err := db.InsertSampleBatch(ctx, []*Sample{s})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDBContext(t, ctx)
			sha := staleTestSHA(41)
			seedSighting(t, db, sha)
			if err := tc.insert(db, sample(sha)); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got, err := db.SampleBySHA256(ctx, sha)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if got == nil {
				t.Fatalf("%s stored no row", tc.name)
			}
			if got.AnalyzedAt == nil {
				t.Errorf("%s dropped AnalyzedAt; the field is on Sample and every write path must honour it", tc.name)
			}
			if got.PURLBase != "pkg:npm/example" {
				t.Errorf("%s dropped PURLBase: got %q; popular and version-drift both select on purl_base <> ''",
					tc.name, got.PURLBase)
			}
			if got.TopTraits != sampleTopTraits {
				t.Errorf("%s dropped TopTraits: got %q; fp-trait selects on top_traits <> '' and the "+
					"unconvicted-hostile trait-directory bar reads it", tc.name, got.TopTraits)
			}
			if got.TraitsVersion != "abc12" {
				t.Errorf("%s dropped TraitsVersion: got %q; the rescan tier selects on "+
					"traits_version != current, so an empty one reads as permanently stale", tc.name, got.TraitsVersion)
			}
			if !got.Corroborated {
				t.Errorf("%s left corroborated false despite a sighting that predates the row; "+
					"the trigger fires on sightings only, so acquit and fallout would take this sample "+
					"even though an outside source names it", tc.name)
			}
		})
	}
}
