package store

import (
	"strings"
	"testing"
	"time"
)

// Health reads arrivals, scans, the queue and the acquirers' backlog from
// the verdict tables.
func TestHealth(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	before := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC) // the archive fixture scans at 15:00 that day
	h, err := st.Health(ctx, before, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !h.LatestArrived.IsZero() || !h.LatestScanned.IsZero() || len(h.Queued) != 0 || h.SightedWait != 0 {
		t.Errorf("empty store health %+v, want nothing", h)
	}

	archive().write(ctx, t, st)
	ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: digestOf("package bytes"), Size: 4000, Path: "incoming/pkg.tgz"},
		Arrival{SHA256: digestOf("unscanned"), Size: 10, Path: "incoming/unscanned"})
	if _, err := st.AddSightings(ctx, []Sighting{{Source: "osv", Subject: "pkg:npm/evil", Claim: "malicious", Basis: "reviewed"}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ClaimAcquisition(ctx, "https://example.test/evil.tgz", time.Hour); err != nil || !ok {
		t.Fatalf("claim: %v, %v", ok, err)
	}
	if err := st.SetPopular(ctx, []Popular{{Name: "pkg:npm/left-pad", Ecosystem: "npm", Source: "top", Rank: 1}}); err != nil {
		t.Fatal(err)
	}

	h, err = st.Health(ctx, before, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if h.LatestArrived.IsZero() || h.LatestScanned.IsZero() {
		t.Errorf("latest arrived %v, scanned %v; want both", h.LatestArrived, h.LatestScanned)
	}
	if h.Depths[QueueNew] != 1 {
		t.Errorf("depths %v, want the unscanned file queued", h.Depths)
	}
	if h.Queued[QueueNew] != 1 || len(h.Queued) != 1 {
		t.Errorf("queued since %v: %v, want the unscanned file, queued since", before, h.Queued)
	}
	// A file queued before the time asked for is waiting, but did not arrive
	// since.
	if h, err := st.Health(ctx, time.Now().Add(time.Hour), time.Now()); err != nil || len(h.Queued) != 0 || h.Depths[QueueNew] != 1 {
		t.Errorf("queued since an hour ahead: %v, depths %v, %v; want nothing arrived and the file still waiting", h.Queued, h.Depths, err)
	}
	if h.OldestUnacquired.IsZero() || h.Unfinished != 1 || h.Popular != 1 {
		t.Errorf("unacquired since %v, unfinished %d, popular %d", h.OldestUnacquired, h.Unfinished, h.Popular)
	}

	w, err := st.Work(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Backlogs) != 1 || w.Backlogs[0].Queued != 1 || w.Backlogs[0].Source != "" {
		t.Errorf("backlogs %+v, want the one queued file", w.Backlogs)
	}
	if len(w.Waiting) != 1 || w.Waiting[0].Path != "incoming/unscanned" || w.Waiting[0].QueuedFor == nil {
		t.Errorf("waiting %+v, want the unscanned file", w.Waiting)
	}
	if len(w.Scanned) != 1 || w.Scanned[0].Class != "hostile" || w.Scanned[0].Path != "incoming/pkg.tgz" {
		t.Errorf("scanned %+v, want the archive at its path", w.Scanned)
	}
	if len(w.Arrived) != 2 {
		t.Errorf("arrived %+v, want both files with a path", w.Arrived)
	}
	if n, err := st.Watermark(ctx); err != nil || n < 3 {
		t.Errorf("watermark %d, %v", n, err)
	}
	if n, err := st.Scanned(ctx); err != nil || n != 1 {
		t.Errorf("scanned %d, %v; want 1", n, err)
	}

	// A cited file whose scan failed 8 times is never handed out again. It
	// is stuck, and its age in the scan queue is no wait for judgement: on
	// 2026-11-22 six such rows paged as a six-day sighted-pinned wait.
	stuck := digestOf("cited, stuck")
	ingest(ctx, t, st, QueueSighted, Arrival{SHA256: stuck, Size: 10, Path: "incoming/stuck"})
	if _, err := st.pool.Exec(ctx, `UPDATE queue SET attempts = 8, queued_at = now() - interval '6 days'
		WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`, stuck); err != nil {
		t.Fatal(err)
	}
	h, err = st.Health(ctx, before, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if h.Stuck != 1 || h.SightedWait != 0 || h.Depths[QueueSighted] != 0 {
		t.Errorf("stuck %d, sighted wait %v, sighted depth %d; want the row counted as stuck and nowhere else",
			h.Stuck, h.SightedWait, h.Depths[QueueSighted])
	}
}

// A result reports the queued scans it completed, each with the priority it
// was queued at, which says whether it was a first scan or a rescan: the
// store keeps only a file's latest scan, so how long ago a file arrived
// cannot tell them apart, and with a weeks-deep first-scan queue nearly every
// first scan is of a file older than any rate window.
func TestCompletedScans(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	pkg, script := digestOf("package bytes"), digestOf("script bytes")
	// Both the archive and the script inside it wait on first scans, the
	// script in its own right.
	ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: pkg, Size: 4000, Path: "incoming/pkg.tgz"},
		Arrival{SHA256: script, Size: 300, Path: "incoming/install.js"})
	if _, err := st.pool.Exec(ctx, `UPDATE queue SET queued_at = now() - interval '3 weeks'`); err != nil {
		t.Fatal(err)
	}

	r := archive()
	failed := &result{header: strings.Replace(r.header, `"files":2`, `"files":1`, 1), files: []map[string]any{{
		"sha256": hexOf(pkg), "size": 4000, "type": "npm",
		"verdict": map[string]any{"outcome": "error", "error": "too many open files"},
	}}}
	if got := failed.write(ctx, t, st); len(got.Completed) != 0 {
		t.Errorf("a failed scan completed %+v; want none, its file still waits", got.Completed)
	}

	got := r.write(ctx, t, st).Completed
	if len(got) != 2 {
		t.Fatalf("completed %+v, want the archive and its member", got)
	}
	for _, c := range got {
		if c.Priority != QueueNew || c.Priority.IsRescan() || time.Since(c.QueuedAt) < 20*24*time.Hour {
			t.Errorf("completed %+v (rescan %v); want a first scan queued three weeks ago", c, c.Priority.IsRescan())
		}
	}

	// Scanned again because its verdict went stale: a rescan, of a file
	// queued just now.
	enqueue(ctx, t, st, QueueStale, pkg)
	r.header = strings.NewReplacer(`"ruleset":"r1"`, `"ruleset":"r2"`, "T15:00:00Z", "T16:00:00Z").Replace(r.header)
	got = r.write(ctx, t, st).Completed
	if len(got) != 1 || got[0].Priority != QueueStale || !got[0].Priority.IsRescan() || time.Since(got[0].QueuedAt) > time.Hour {
		t.Errorf("completed %+v; want the one stale rescan, queued just now", got)
	}

	// A scan of a file nobody queued completes nothing.
	r.header = strings.Replace(r.header, "T16:00:00Z", "T17:00:00Z", 1)
	if got := r.write(ctx, t, st).Completed; len(got) != 0 {
		t.Errorf("completed %+v; want none", got)
	}
}

// Every priority is a first scan but the ones that queue a file again.
func TestPriorityIsRescan(t *testing.T) {
	for p, want := range map[Priority]bool{
		QueueSighted: false, QueueUpload: false, QueueCompromised: false, QueueBigArchive: false, QueueNew: false,
		QueueRequested: true, QueueDescribe: true, QueueRepair: true, QueueStale: true,
	} {
		if got := p.IsRescan(); got != want {
			t.Errorf("Priority(%d).IsRescan() = %v, want %v", p, got, want)
		}
	}
}
