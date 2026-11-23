package store

import (
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
	if !h.LatestArrived.IsZero() || !h.LatestScanned.IsZero() || h.Scanned != 0 || h.SightedWait != 0 {
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
	if h.Scanned != 1 || h.Rescanned != 0 {
		t.Errorf("scanned %d, rescanned %d; want the archive's one scan, a first", h.Scanned, h.Rescanned)
	}
	if h.Depths[QueueNew] != 1 {
		t.Errorf("depths %v, want the unscanned file queued", h.Depths)
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
