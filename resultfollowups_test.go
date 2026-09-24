package hopper

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests for what happens around a stored verdict: who produced it (result
// attribution), which archives it makes stale (parent requeue on a crit rise),
// and which sibling releases a conviction makes suspect (sibling rescan). Each
// runs on SQLite and, with HOPPER_TEST_PG_DSN set, on Postgres, because every
// one of these is a pair of hand-written twins.

func hexSHA(n int) string { return fmt.Sprintf("%064x", n) }

// execBoth runs one UPDATE written with $N placeholders on either backend,
// rewriting them to ? for SQLite. Times are passed as time.Time and formatted
// the way SQLite stores them.
func execBoth(t *testing.T, ctx context.Context, db *DB, stmt string, args ...any) {
	t.Helper()
	if db.pool != nil {
		if _, err := db.pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
		return
	}
	for i := len(args); i >= 1; i-- {
		stmt = strings.ReplaceAll(stmt, fmt.Sprintf("$%d", i), "?")
	}
	for i, a := range args {
		if tm, ok := a.(time.Time); ok {
			args[i] = tm.UTC().Format(time.RFC3339Nano)
		}
	}
	if _, err := db.lite.ExecContext(ctx, stmt, args...); err != nil {
		t.Fatalf("exec %q: %v", stmt, err)
	}
}

func attributionOf(t *testing.T, ctx context.Context, db *DB, sha string) ResultAttribution {
	t.Helper()
	by, err := db.AnalysisAttribution(ctx, sha)
	if err != nil {
		t.Fatalf("AnalysisAttribution(%s): %v", sha, err)
	}
	return by
}

func rescanPriorityOf(t *testing.T, ctx context.Context, db *DB, sha string) int {
	t.Helper()
	var p int
	var err error
	if db.pool != nil {
		err = db.pool.QueryRow(ctx, `SELECT rescan_priority FROM samples WHERE sha256 = $1`, sha).Scan(&p)
	} else {
		err = db.lite.QueryRowContext(ctx, `SELECT rescan_priority FROM samples WHERE sha256 = ?`, sha).Scan(&p)
	}
	if err != nil {
		t.Fatalf("rescan_priority %s: %v", sha, err)
	}
	return p
}

// critEnvelope is a single-file v8 envelope whose one trait fires at crit.
func critEnvelope(sha string, crit int) []byte {
	return fmt.Appendf(nil,
		`{"files":[{"sha":%q,"type":"javascript","depth":0,"traits":[{"id":"t/x","crit":%d}]}]}`, sha, crit)
}

func storeCrit(t *testing.T, ctx context.Context, db *DB, sha string, crit int, tv string, by ResultAttribution) StoreStats {
	t.Helper()
	stats, err := db.StoreResult(ctx, sha, critEnvelope(sha, crit), nil, nil, nil, tv, by)
	if err != nil {
		t.Fatalf("StoreResult(%s, crit %d, %s): %v", sha[:6], crit, tv, err)
	}
	return stats
}

func insertTop(t *testing.T, ctx context.Context, db *DB, sha, label, purl, version string) {
	t.Helper()
	mustInsert(t, ctx, db, &Sample{
		SHA256: sha, Source: "test", Label: label, LabelSource: "test",
		PURLBase: purl, Version: version, Path: "test/" + sha, SizeBytes: 64,
	})
}

// The row records which worker produced its verdict, and what that worker said
// it was running, in the same write as the verdict — and keeps crediting the
// producer of the verdict that actually stands.
func TestStoreResultRecordsAttribution(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			sha := hexSHA(0xa77)
			insertTop(t, ctx, db, sha, "unknown", "", "")

			if by, err := db.AnalysisAttribution(ctx, sha); err != nil || by != (ResultAttribution{}) {
				t.Fatalf("unanalyzed attribution = %+v, %v; want zero", by, err)
			}

			first := ResultAttribution{Worker: "nazgul:10.0.0.7", Version: "0.9.1", Traits: "b8c1c"}
			storeCrit(t, ctx, db, sha, 3, "tv1", first)
			if got, err := db.AnalysisAttribution(ctx, sha); err != nil || got != first {
				t.Fatalf("attribution = %+v, %v; want %+v", got, err, first)
			}

			// A redundant re-post (same traits version) writes nothing, so the
			// verdict that stands is still the first worker's, and so is the credit.
			other := ResultAttribution{Worker: "smaug:10.0.0.9", Version: "0.9.2", Traits: "c0ffe"}
			if stats := storeCrit(t, ctx, db, sha, 3, "tv1", other); !stats.Unchanged {
				t.Fatal("same-traits re-post should take the unchanged fast path")
			}
			if got := attributionOf(t, ctx, db, sha); got != first {
				t.Errorf("redundant re-post moved attribution to %+v; the stored verdict is still %+v's", got, first)
			}

			// A real re-analysis replaces verdict and credit together.
			storeCrit(t, ctx, db, sha, 3, "tv2", other)
			if got := attributionOf(t, ctx, db, sha); got != other {
				t.Errorf("renewal attribution = %+v, want %+v", got, other)
			}

			// A write-back through /api/cleave-result replaces the verdict too, and
			// must not leave the previous worker credited with it.
			if err := db.UpdateCleaveResult(ctx, sha, critEnvelope(sha, 5), nil, "tv3"); err != nil {
				t.Fatal(err)
			}
			want := ResultAttribution{Worker: cleaveWriteBackAttribution}
			if got := attributionOf(t, ctx, db, sha); got != want {
				t.Errorf("write-back attribution = %+v, want %+v", got, want)
			}

			if _, err := db.AnalysisAttribution(ctx, hexSHA(0xdead)); !errors.Is(err, ErrNotFound) {
				t.Errorf("absent sample: err = %v, want ErrNotFound", err)
			}
		})
	}
}

// A renewal that raises a sample's max_crit queues the top-level archives
// containing it — only the ones the rise can have made stale — and nothing else
// does: not a first analysis, not a renewal that leaves crit where it was.
func TestCritRiseRequeuesContainingArchives(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			child := hexSHA(0xc1)
			stale := hexSHA(0x01)     // analyzed under old rules, less severe: requeue
			severe := hexSHA(0x02)    // already at least as severe as the child now is
			current := hexSHA(0x03)   // analyzed under the rules that produced the rise
			asked := hexSHA(0x04)     // an operator already asked for it: never demoted
			unrelated := hexSHA(0x05) // does not contain the child
			for _, p := range []string{stale, severe, current, asked, unrelated} {
				insertTop(t, ctx, db, p, "unknown", "", "")
				storeCrit(t, ctx, db, p, 3, "tv1", ResultAttribution{})
			}
			execBoth(t, ctx, db, `UPDATE samples SET max_crit = 9 WHERE sha256 = $1`, severe)
			execBoth(t, ctx, db, `UPDATE samples SET traits_version = 'tv3' WHERE sha256 = $1`, current)
			execBoth(t, ctx, db, `UPDATE samples SET rescan_priority = 2 WHERE sha256 = $1`, asked)

			insertTop(t, ctx, db, child, "unknown", "", "")
			for _, p := range []string{stale, severe, current, asked} {
				if err := db.UpsertLocation(ctx, &SampleLocation{
					SHA256: child, ParentSHA256: p, Path: p + "!!lib/index.js", Filename: "index.js",
				}); err != nil {
					t.Fatal(err)
				}
			}
			priorities := func() map[string]int {
				out := map[string]int{}
				for _, p := range []string{stale, severe, current, asked, unrelated} {
					out[p] = rescanPriorityOf(t, ctx, db, p)
				}
				return out
			}
			untouched := map[string]int{stale: 0, severe: 0, current: 0, asked: 2, unrelated: 0}

			// First analysis: nothing to have gone stale against.
			if s := storeCrit(t, ctx, db, child, 2, "tv1", ResultAttribution{}); s.ParentsRequeued != 0 {
				t.Errorf("first analysis requeued %d archives", s.ParentsRequeued)
			}
			// Renewal without a rise.
			if s := storeCrit(t, ctx, db, child, 2, "tv2", ResultAttribution{}); s.ParentsRequeued != 0 {
				t.Errorf("renewal at the same crit requeued %d archives", s.ParentsRequeued)
			}
			for p, want := range untouched {
				if got := priorities()[p]; got != want {
					t.Fatalf("before the rise, %s priority = %d, want %d", p[:6], got, want)
				}
			}

			// The rise.
			s := storeCrit(t, ctx, db, child, 8, "tv3", ResultAttribution{})
			if s.PriorMaxCrit != 2 || s.ParentsRequeued != 1 {
				t.Errorf("rise stats: prior %d requeued %d, want prior 2 requeued 1", s.PriorMaxCrit, s.ParentsRequeued)
			}
			want := map[string]int{stale: 1, severe: 0, current: 0, asked: 2, unrelated: 0}
			for p, w := range want {
				if got := priorities()[p]; got != w {
					t.Errorf("after the rise, %s priority = %d, want %d", p[:6], got, w)
				}
			}
			// The requeued archive is what the repair tier now hands out.
			jobs, err := db.RepairCandidates(ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != 1 || jobs[0].SHA256 != stale {
				t.Errorf("repair tier = %+v, want exactly the stale archive", jobs)
			}
		})
	}
}

// The requeue is bounded however many archives hold the sample.
func TestCritRiseRequeueIsBounded(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			child := hexSHA(0xc2)
			insertTop(t, ctx, db, child, "unknown", "", "")
			storeCrit(t, ctx, db, child, 1, "tv1", ResultAttribution{})
			var locs []*SampleLocation
			for i := range maxParentRequeue + 12 {
				p := hexSHA(0x10000 + i)
				insertTop(t, ctx, db, p, "unknown", "", "")
				mustAnalyzeWithTraits(t, ctx, db, p, 0, `{"l":1}`)
				locs = append(locs, &SampleLocation{SHA256: child, ParentSHA256: p, Path: p + "!!x.js"})
			}
			if err := db.UpsertLocationBatch(ctx, locs); err != nil {
				t.Fatal(err)
			}
			if s := storeCrit(t, ctx, db, child, 9, "tv2", ResultAttribution{}); s.ParentsRequeued != maxParentRequeue {
				t.Errorf("requeued %d archives, want the bound %d", s.ParentsRequeued, maxParentRequeue)
			}
		})
	}
}

// A conviction queues the package's other artifacts that are still unknown and
// were judged on older evidence — boundedly, newest first — and leaves the rest.
func TestConvictionQueuesStaleSiblings(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			const purl = "pkg:npm/%40memtensor/memos-cloud-openclaw-plugin"
			now := time.Now().UTC()
			convicted := hexSHA(0x121)
			older := hexSHA(0x119)       // unknown, analyzed earlier under old rules: queue
			olderStill := hexSHA(0x118)  // likewise
			sameRelease := hexSHA(0x122) // another artifact of the convicted release: queue
			good := hexSHA(0x120)        // already judged good: leave
			current := hexSHA(0x124)     // analyzed after the conviction's evidence, same rules: leave
			pending := hexSHA(0x125)     // never analyzed: already in line, leave
			asked := hexSHA(0x117)       // interactive rescan pending: never demoted
			foreign := hexSHA(0x999)     // another package: leave

			rows := []struct {
				sha, label, purl, version, tv string
				analyzedAt                    time.Time
			}{
				{convicted, "unknown", purl, "0.1.21", "tv9", now.Add(-time.Hour)},
				{older, "unknown", purl, "0.1.19", "tv1", now.Add(-3 * time.Hour)},
				{olderStill, "unknown", purl, "0.1.18", "", now.Add(-4 * time.Hour)},
				{sameRelease, "unknown", purl, "0.1.21", "tv1", now.Add(-2 * time.Hour)},
				{good, "good", purl, "0.1.20", "tv1", now.Add(-3 * time.Hour)},
				{current, "unknown", purl, "0.1.24", "tv9", now.Add(-time.Minute)},
				{asked, "unknown", purl, "0.1.17", "tv1", now.Add(-5 * time.Hour)},
				{foreign, "unknown", "pkg:npm/lodash", "4.17.21", "tv1", now.Add(-5 * time.Hour)},
			}
			for _, r := range rows {
				insertTop(t, ctx, db, r.sha, r.label, r.purl, r.version)
				mustAnalyzeWithTraits(t, ctx, db, r.sha, 0, "")
				execBoth(t, ctx, db, `UPDATE samples SET traits_version = $1, analyzed_at = $2 WHERE sha256 = $3`,
					r.tv, r.analyzedAt, r.sha)
			}
			insertTop(t, ctx, db, pending, "unknown", purl, "0.1.25")
			execBoth(t, ctx, db, `UPDATE samples SET rescan_priority = 2 WHERE sha256 = $1`, asked)

			// The conviction as cyclotron makes it: a triage ruling of bad.
			if ok, err := db.prepareLocationMove(ctx, convicted, "test/"+convicted, "bad/foraged-quarantine/"+convicted,
				&LocationRelabel{Label: labelBad, Source: "cyclotron:sighted-pinned"}); err != nil || !ok {
				t.Fatalf("prepareLocationMove = %v, %v", ok, err)
			}
			want := map[string]int{
				older: 1, olderStill: 1, sameRelease: 1,
				good: 0, current: 0, pending: 0, asked: 2, foreign: 0, convicted: 0,
			}
			for sha, w := range want {
				if got := rescanPriorityOf(t, ctx, db, sha); got != w {
					t.Errorf("%s priority = %d, want %d", sha[len(sha)-3:], got, w)
				}
			}
			// Idempotent: everything eligible is already queued.
			if n, err := db.QueueSiblingRescans(ctx, convicted); err != nil || n != 0 {
				t.Errorf("second QueueSiblingRescans = %d, %v; want 0", n, err)
			}
			// Reclassify is a conviction too, and a sample with no package has
			// no siblings.
			loner := hexSHA(0x777)
			insertTop(t, ctx, db, loner, "unknown", "", "")
			if err := db.Reclassify(ctx, loner, labelBad, "operator"); err != nil {
				t.Fatal(err)
			}
			if n, err := db.QueueSiblingRescans(ctx, loner); err != nil || n != 0 {
				t.Errorf("purl-less conviction queued %d siblings, %v", n, err)
			}
		})
	}
}

// A conviction in a package with a long history queues at most
// maxSiblingRescan siblings, and spends the bound on the newest.
func TestConvictionSiblingRescanIsBounded(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			const purl = "pkg:pypi/memoryos"
			convicted := hexSHA(0x5000)
			insertTop(t, ctx, db, convicted, "unknown", purl, "2.0.34")
			mustAnalyzeWithTraits(t, ctx, db, convicted, 0, "")
			execBoth(t, ctx, db, `UPDATE samples SET traits_version = 'tv9' WHERE sha256 = $1`, convicted)
			past := time.Now().UTC().Add(-time.Hour)
			var siblings []string
			for i := range maxSiblingRescan + 6 {
				sha := hexSHA(0x6000 + i)
				siblings = append(siblings, sha) // inserted oldest first
				insertTop(t, ctx, db, sha, "unknown", purl, fmt.Sprintf("1.%d", i))
				mustAnalyzeWithTraits(t, ctx, db, sha, 0, "")
				execBoth(t, ctx, db, `UPDATE samples SET analyzed_at = $1 WHERE sha256 = $2`, past, sha)
			}
			if err := db.Reclassify(ctx, convicted, labelBad, "cyclotron:sighted-pinned"); err != nil {
				t.Fatal(err)
			}
			queued := 0
			for i, sha := range siblings {
				p := rescanPriorityOf(t, ctx, db, sha)
				if p == 1 {
					queued++
				}
				if i < 6 && p != 0 {
					t.Errorf("sibling %d (among the oldest) was queued; the bound goes to the newest", i)
				}
			}
			if queued != maxSiblingRescan {
				t.Errorf("queued %d siblings, want the bound %d", queued, maxSiblingRescan)
			}
		})
	}
}

// The pinned queue serves the oldest first sighting first, and at most
// sightedPinnedPerPackage rows of one package per round — so a source listing
// many versions of one package cannot take the page, and a fresh claim cannot
// jump rows that have waited longer.
func TestTriageSightedPinnedOrdersFIFOAcrossPackages(t *testing.T) {
	for _, b := range testBackends {
		t.Run(b.name, func(t *testing.T) {
			db := b.open(t)
			ctx := context.Background()
			now := time.Now().UTC()
			type row struct{ sha, purl, version string }
			var flood []row
			add := func(n int, purl, version string) string {
				sha := hexSHA(0x7000 + n)
				insertTop(t, ctx, db, sha, "unknown", purl, version)
				mustAnalyzeWithTraits(t, ctx, db, sha, 0, "")
				return sha
			}
			// One source lists nineteen versions of one package at once.
			var sightings []Sighting
			for i := range 19 {
				v := fmt.Sprintf("0.1.%d", i)
				flood = append(flood, row{add(i, "pkg:npm/%40memtensor/memos-cloud-openclaw-plugin", v), "", v})
				sightings = append(sightings, Sighting{
					Source: "flood", Subject: "pkg:npm/%40memtensor/memos-cloud-openclaw-plugin", Affected: v,
				})
			}
			oldest := add(100, "pkg:pypi/memoryos", "2.0.34")
			older := add(101, "pkg:npm/older", "1.0.0")
			newest := add(102, "pkg:npm/newest", "3.0.0")
			sightings = append(sightings,
				Sighting{Source: "oldest", Subject: "pkg:pypi/memoryos", Affected: "2.0.34"},
				Sighting{Source: "older", Subject: "pkg:npm/older", Affected: "1.0.0"},
				Sighting{Source: "newest", Subject: "pkg:npm/newest", Affected: "3.0.0"},
				// A later re-assertion of the oldest claim by another source must not
				// move it back in line: its place is its FIRST sighting.
				Sighting{Source: "echo", Subject: "pkg:pypi/memoryos", Affected: "2.0.34"},
			)
			if _, err := db.AddSightings(ctx, sightings); err != nil {
				t.Fatal(err)
			}
			for source, at := range map[string]time.Time{
				"oldest": now.Add(-5 * time.Hour), "older": now.Add(-3 * time.Hour),
				"flood": now.Add(-2 * time.Hour), "newest": now.Add(-time.Hour),
				"echo": now.Add(-time.Minute),
			} {
				execBoth(t, ctx, db, `UPDATE sightings SET first_seen = $1 WHERE source = $2`, at, source)
			}

			got, err := db.TriageSightedPinned(ctx, 10, now.Add(-SightedPinnedWindow), TriageFilter{})
			if err != nil {
				t.Fatal(err)
			}
			// Round one: every package's first sightedPinnedPerPackage rows, the
			// package sighted first going first. Round two: the flood's next three.
			want := []string{
				oldest, older, flood[0].sha, flood[1].sha, flood[2].sha, newest,
				flood[3].sha, flood[4].sha, flood[5].sha, flood[6].sha,
			}
			if len(got) != len(want) {
				t.Fatalf("got %d rows, want %d", len(got), len(want))
			}
			for i := range want {
				if got[i].SHA256 != want[i] {
					t.Errorf("row %d = %s, want %s", i, got[i].SHA256[60:], want[i][60:])
				}
			}

			// Ordering changed; membership did not. The whole population is
			// served, and none of it leaks into the ordinary sighted queue.
			all, err := db.TriageSightedPinned(ctx, 100, now.Add(-SightedPinnedWindow), TriageFilter{})
			if err != nil || len(all) != 22 {
				t.Fatalf("full pinned selection = %d rows, %v; want 22", len(all), err)
			}
			ordinary, err := db.TriageSighted(ctx, 100, now.Add(-SightedPinnedWindow), TriageFilter{})
			if err != nil {
				t.Fatal(err)
			}
			if len(ordinary) != 0 {
				t.Errorf("ordinary sighted queue holds %d pinned rows; the queues must partition", len(ordinary))
			}
		})
	}
}
