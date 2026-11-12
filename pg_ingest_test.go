package hopper

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func observationVersionPG(t *testing.T, db *DB, table, sha string) string {
	t.Helper()
	var version string
	if err := db.pool.QueryRow(t.Context(), `SELECT xmin::text || ':' || ctid::text FROM `+table+` WHERE sha256=$1`, sha).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

// writeObservationPG exercises both ordinary PostgreSQL ingestion entry points.
func writeObservationPG(t *testing.T, db *DB, s *Sample, batch bool) int64 {
	t.Helper()
	if batch {
		n, _, err := db.insertSampleBatchPG(t.Context(), []*Sample{s})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	changed, err := db.insertSampleNewPG(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		return 1
	}
	return 0
}

func TestPGObservationUnchangedRows(t *testing.T) {
	db := openDisposablePG(t)
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, batch := range []bool{false, true} {
		for i, tc := range []struct {
			name                          string
			label, source, skip           string
			incomingLabel, incomingSource string
		}{
			{"ordinary", "good", "filesystem", "", "good", "filesystem"},
			{"marker", "good", "marker", "misclassified", "good", "marker"},
			{"resolved conflict", "bad", "conflict", "conflict", "good", "filesystem"},
			{"reviewed marker", "inconclusive", "human-review", "missing", "bad", "marker"},
			{"reviewed skip", "dual-use", "human-review", "unsupported", "unknown", "filesystem"},
		} {
			t.Run(fmt.Sprintf("batch=%v/%s", batch, tc.name), func(t *testing.T) {
				s := &Sample{SHA256: hexSHA(81000 + i), Path: "good/file", Filename: "file", Label: tc.label, LabelSource: tc.source, Skip: tc.skip, MarkerMtime: &stamp}
				if batch {
					s.SHA256 = hexSHA(81100 + i)
				}
				if _, err := db.insertSampleNewPG(t.Context(), s); err != nil {
					t.Fatal(err)
				}
				beforeSample := observationVersionPG(t, db, "samples", s.SHA256)
				beforeLocation := observationVersionPG(t, db, "sample_locations", s.SHA256)
				s.Label, s.LabelSource = tc.incomingLabel, tc.incomingSource
				for range 2 {
					if n := writeObservationPG(t, db, s, batch); n != 0 {
						t.Fatalf("repeat updated %d samples", n)
					}
				}
				if got := observationVersionPG(t, db, "samples", s.SHA256); got != beforeSample {
					t.Fatalf("unchanged sample rewritten: %s -> %s", beforeSample, got)
				}
				if got := observationVersionPG(t, db, "sample_locations", s.SHA256); got != beforeLocation {
					t.Fatalf("unchanged location rewritten: %s -> %s", beforeLocation, got)
				}
				newer := stamp.Add(time.Hour)
				s.MarkerMtime = &newer
				writeObservationPG(t, db, s, batch)
				var got time.Time
				if err := db.pool.QueryRow(t.Context(), `SELECT marker_mtime FROM samples WHERE sha256=$1`, s.SHA256).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if !got.Equal(newer) {
					t.Fatalf("marker refresh=%v want %v", got, newer)
				}
				beforeSample = observationVersionPG(t, db, "samples", s.SHA256)
				s.MarkerMtime = nil
				writeObservationPG(t, db, s, batch)
				if got := observationVersionPG(t, db, "samples", s.SHA256); got != beforeSample {
					t.Fatal("absent marker timestamp rewrote sample")
				}
			})
		}
	}
}

func TestPGObservationChanges(t *testing.T) {
	db := openDisposablePG(t)
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			sha := hexSHA(81200)
			if batch {
				sha = hexSHA(81201)
			}
			s := &Sample{SHA256: sha, Path: "good/file", Filename: "file", Label: "unknown"}
			write := func() {
				t.Helper()
				if n := writeObservationPG(t, db, s, batch); n != 1 {
					t.Fatalf("changed observation updated %d samples", n)
				}
			}
			write()
			for _, step := range []struct{ label, source, skip, wantLabel, wantSource, wantSkip string }{
				{"good", "filesystem", "", "good", "filesystem", ""},
				{"bad", "filesystem", "", "bad", "conflict", "conflict"},
				{"good", "marker", "", "good", "marker", "misclassified"},
				{"good", "filesystem", "", "good", "filesystem", ""},
			} {
				s.Label, s.LabelSource, s.Skip = step.label, step.source, step.skip
				write()
				var label, source, skip string
				if err := db.pool.QueryRow(t.Context(), `SELECT label,label_source,skip FROM samples WHERE sha256=$1`, sha).Scan(&label, &source, &skip); err != nil {
					t.Fatal(err)
				}
				if label != step.wantLabel || source != step.wantSource || skip != step.wantSkip {
					t.Fatalf("transition: %s/%s/%s, want %+v", label, source, skip, step)
				}
			}
			for _, skip := range []string{"missing", "unsupported"} {
				if _, err := db.pool.Exec(t.Context(), `UPDATE samples SET skip=$2 WHERE sha256=$1`, sha, skip); err != nil {
					t.Fatal(err)
				}
				write()
				var got string
				if err := db.pool.QueryRow(t.Context(), `SELECT skip FROM samples WHERE sha256=$1`, sha).Scan(&got); err != nil || got != "" {
					t.Fatalf("recover %s: %q %v", skip, got, err)
				}
			}
			// Each enrichment must work by itself, without an unrelated path or label
			// change making the conflict predicate true.
			stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			for _, change := range []func(){
				func() { s.Filename = "corrected" },
				func() { s.Domain = "example.org" },
				func() { s.Version = "1.0" },
				func() { s.FetchedAt = &stamp },
				func() { s.Package = "guess" },
				func() { s.PURLBase = "pkg:npm/guess" },
				func() {
					s.Package = "authoritative"
					s.PURLBase = "pkg:npm/authoritative"
					s.Version = "2.0"
					s.Provenance = []byte(`{"registry":true}`)
				},
			} {
				change()
				write()
			}
			var filename, domain, version, pkg, purl string
			var fetched time.Time
			if err := db.pool.QueryRow(t.Context(), `SELECT filename,domain,version,package,purl_base,fetched_at FROM samples WHERE sha256=$1`, sha).Scan(&filename, &domain, &version, &pkg, &purl, &fetched); err != nil {
				t.Fatal(err)
			}
			if filename != "corrected" || domain != "example.org" || version != "2.0" || pkg != "authoritative" || purl != "pkg:npm/authoritative" || !fetched.Equal(stamp) {
				t.Fatalf("enrichment lost: %s %s %s %s %s %v", filename, domain, version, pkg, purl, fetched)
			}
			before := observationVersionPG(t, db, "samples", sha)
			s.Package, s.Version, s.PURLBase = "other", "3.0", "pkg:npm/other"
			s.Provenance = []byte(`{"registry":false}`)
			writeObservationPG(t, db, s, batch)
			if got := observationVersionPG(t, db, "samples", sha); got != before {
				t.Fatal("settled provenance rewritten")
			}
		})
	}
}

func stageObservationPG(t *testing.T, tx pgx.Tx, s *Sample) {
	t.Helper()
	if _, err := tx.Exec(t.Context(), insertBatchStagingCore+` ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.CopyFrom(t.Context(), pgx.Identifier{"_staging"}, insertBatchStagingCols, pgx.CopyFromRows(sampleStagingRows([]*Sample{s}))); err != nil {
		t.Fatal(err)
	}
}

func TestPGObservationLocationMetadata(t *testing.T) {
	db := openDisposablePG(t)
	s := &Sample{SHA256: hexSHA(81210), Parent: hexSHA(81211), Path: "good/p.tgz!!file", Label: "unknown"}
	if _, err := db.insertSampleNewPG(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	sampleVersion := observationVersionPG(t, db, "samples", s.SHA256)
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, change := range []func(){
		func() { s.Source = "collector" },
		func() { s.Feed = "npm" },
		func() { s.Ecosystem = "javascript" },
		func() { s.LocationRel = "unpacked" },
		func() { s.Mtime = &stamp },
	} {
		before := observationVersionPG(t, db, "sample_locations", s.SHA256)
		change()
		// Duplicate input rows must still yield one location, without PostgreSQL
		// trying to update the same conflicting row twice in one statement.
		if _, _, err := db.insertSampleBatchPG(t.Context(), []*Sample{s, s}); err != nil {
			t.Fatal(err)
		}
		after := observationVersionPG(t, db, "sample_locations", s.SHA256)
		if after == before {
			t.Fatal("location metadata change was filtered out")
		}
		if _, _, err := db.insertSampleBatchPG(t.Context(), []*Sample{s}); err != nil {
			t.Fatal(err)
		}
		if got := observationVersionPG(t, db, "sample_locations", s.SHA256); got != after {
			t.Fatal("repeated location metadata rewrote the row")
		}
	}
	before := observationVersionPG(t, db, "sample_locations", s.SHA256)
	s.Source, s.Feed, s.Ecosystem, s.LocationRel, s.Mtime = "another collector", "", "", "", nil
	if _, _, err := db.insertSampleBatchPG(t.Context(), []*Sample{s}); err != nil {
		t.Fatal(err)
	}
	if got := observationVersionPG(t, db, "sample_locations", s.SHA256); got != before {
		t.Fatal("blank metadata or a later producer overwrote existing metadata")
	}
	var source, feed, ecosystem, rel string
	var mtime time.Time
	if err := db.pool.QueryRow(t.Context(), `SELECT source,feed,ecosystem,rel,mtime FROM sample_locations WHERE sha256=$1`, s.SHA256).
		Scan(&source, &feed, &ecosystem, &rel, &mtime); err != nil {
		t.Fatal(err)
	}
	if source != "collector" || feed != "npm" || ecosystem != "javascript" || rel != "unpacked" || !mtime.Equal(stamp) {
		t.Fatalf("metadata lost: %s %s %s %s %v", source, feed, ecosystem, rel, mtime)
	}
	if got := observationVersionPG(t, db, "samples", s.SHA256); got != sampleVersion {
		t.Fatal("member occurrence changed the shared sample row")
	}
}

func TestPGObservationUnchangedRowsNotLocked(t *testing.T) {
	db := openDisposablePG(t)
	for i, table := range []string{"samples", "sample_locations"} {
		t.Run(table, func(t *testing.T) {
			s := &Sample{SHA256: hexSHA(81300 + i), Path: "good/file", Filename: "file", Label: "bad", LabelSource: "conflict", Skip: "conflict"}
			if _, err := db.insertSampleNewPG(t.Context(), s); err != nil {
				t.Fatal(err)
			}
			s.Label, s.LabelSource = "good", "filesystem"
			tx, err := db.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context()) //nolint:errcheck // test cleanup
			stageObservationPG(t, tx, s)
			query := insertBatchStagingInsert
			if table == "sample_locations" {
				query = locationsFromStagingPG
			}
			if tag, err := tx.Exec(t.Context(), query); err != nil || tag.RowsAffected() != 0 {
				t.Fatalf("repeat: %v %v", tag, err)
			}
			// The ingestion transaction is still open. An UPDATE-strength lock in a
			// second session must succeed immediately, not wait for that transaction.
			other, err := db.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer other.Rollback(t.Context()) //nolint:errcheck // test cleanup
			if _, err := other.Exec(t.Context(), `SELECT id FROM `+table+` WHERE sha256=$1 FOR UPDATE NOWAIT`, s.SHA256); err != nil {
				t.Fatalf("unchanged observation holds a row lock: %v", err)
			}
		})
	}
}

func TestPGObservationConcurrentInsert(t *testing.T) {
	db := openDisposablePG(t)
	for i, table := range []string{"samples", "sample_locations"} {
		for j, feed := range []string{"original", "enriched"} {
			t.Run(table+"/"+feed, func(t *testing.T) {
				testConcurrentObservationPG(t, db, table, feed, hexSHA(81400+i*10+j))
			})
		}
	}
}

func testConcurrentObservationPG(t *testing.T, db *DB, table, feed, sha string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	s := &Sample{SHA256: sha, Path: "good/race", Label: "unknown", Feed: "original"}
	if table == "sample_locations" {
		if _, err := db.pool.Exec(ctx, `INSERT INTO samples(sha256) VALUES($1)`, s.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	first, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(t.Context()) //nolint:errcheck // test cleanup
	stageObservationPG(t, first, s)
	query := insertBatchStagingInsert
	if table == "sample_locations" {
		query = locationsFromStagingPG
	}
	if _, err := first.Exec(ctx, query); err != nil {
		t.Fatal(err)
	}
	second, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(t.Context()) //nolint:errcheck // test cleanup
	s.Feed = feed
	stageObservationPG(t, second, s)
	type result struct {
		tag pgconn.CommandTag
		err error
	}
	done := make(chan result, 1)
	go func() { tag, err := second.Exec(ctx, query); done <- result{tag, err} }()
	// Ensure the second statement took its snapshot before the first commits:
	// its pre-filter cannot see the competing insert, so ON CONFLICT must
	// resolve the duplicate and recheck whether the feed actually changes.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := db.pool.QueryRow(ctx, `SELECT $1::int = ANY(pg_blocking_pids($2::int))`, first.Conn().PgConn().PID(), second.Conn().PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case r := <-done:
			t.Fatalf("second insert did not wait for competing row: %+v", r)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	want := int64(0)
	if feed == "enriched" {
		want = 1
	}
	if r.err != nil || r.tag.RowsAffected() != want {
		t.Fatalf("racing upsert: rows=%d err=%v want %d", r.tag.RowsAffected(), r.err, want)
	}
	if err := second.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	var got string
	if err := db.pool.QueryRow(ctx, `SELECT count(*),min(feed) FROM `+table+` WHERE sha256=$1`, s.SHA256).Scan(&n, &got); err != nil {
		t.Fatal(err)
	}
	if n != 1 || got != feed {
		t.Fatalf("concurrent result: rows=%d feed=%q", n, got)
	}
}
