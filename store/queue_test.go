package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"
)

// place records a location for the file with digest sha, as ingest will.
func place(ctx context.Context, t *testing.T, st *Store, sha []byte, path string) {
	t.Helper()
	if _, err := st.pool.Exec(ctx, `INSERT INTO locations (path, sample_id)
		SELECT $2, id FROM samples WHERE sha256 = $1`, sha, path); err != nil {
		t.Fatal(err)
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func digestOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func priorities(ctx context.Context, t *testing.T, st *Store) map[string]Priority {
	t.Helper()
	rows, err := st.pool.Query(ctx, `SELECT encode(s.sha256, 'hex'), q.priority FROM queue q JOIN samples s ON s.id = q.sample_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]Priority{}
	for rows.Next() {
		var sha string
		var p Priority
		if err := rows.Scan(&sha, &p); err != nil {
			t.Fatal(err)
		}
		out[sha] = p
	}
	return out
}

// enqueue queues a scan of each file at priority p, for tests that start
// from the queue: Ingest, Rescan and the sweep are what queue files.
func enqueue(ctx context.Context, t *testing.T, st *Store, p Priority, shas ...[]byte) {
	t.Helper()
	if _, err := st.pool.Exec(ctx, `INSERT INTO queue (sample_id, priority)
		SELECT id, $2 FROM samples WHERE sha256 = ANY($1) ORDER BY id
		ON CONFLICT (sample_id) DO UPDATE SET priority = least(queue.priority, EXCLUDED.priority)`, shas, int16(p)); err != nil {
		t.Fatal(err)
	}
}

func TestQueueClaims(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	small, big, nowhere := digestOf("small"), digestOf("big"), digestOf("nowhere")
	if _, err := st.pool.Exec(ctx, `INSERT INTO samples (sha256, size_bytes) VALUES ($1, 10), ($2, $4), ($3, 10)`,
		small, big, nowhere, int64(bigFile)+1); err != nil {
		t.Fatal(err)
	}
	place(ctx, t, st, small, "pool/small")
	place(ctx, t, st, big, "pool/big.iso")

	enqueue(ctx, t, st, QueueNew, small, nowhere)
	enqueue(ctx, t, st, QueueBigArchive, big)

	jobs, err := st.Candidates(ctx, QueueNew, 10, 0)
	if err != nil || len(jobs) != 1 || jobs[0].Path != "pool/small" {
		t.Fatalf("candidates %+v, %v: want the small file only; the other has nowhere to be read from", jobs, err)
	}
	if jobs, err := st.Candidates(ctx, QueueBigArchive, 10, 1<<20); err != nil || len(jobs) != 0 {
		t.Errorf("candidates %+v, %v: a file over the worker's limit was offered", jobs, err)
	}
	// postdoc advertises its limit in bytes; 16 GiB does not fit 32 bits.
	if jobs, err := st.Candidates(ctx, QueueBigArchive, 10, 16<<30); err != nil || len(jobs) != 1 {
		t.Errorf("candidates %+v, %v: want the big file under a 16 GiB limit", jobs, err)
	}

	hour := []time.Duration{time.Hour}
	got, err := st.Lease(ctx, []string{jobs[0].SHA256}, hour)
	if err != nil || len(got) != 1 || got[0] != hexOf(small) {
		t.Fatalf("lease %v, %v", got, err)
	}
	if again, err := st.Lease(ctx, got, hour); err != nil || len(again) != 0 {
		t.Errorf("a second lease of a leased file got %v, %v", again, err)
	}
	if jobs, err := st.Candidates(ctx, QueueNew, 10, 0); err != nil || len(jobs) != 0 {
		t.Errorf("a leased file is still a candidate: %+v, %v", jobs, err)
	}
	if err := st.Release(ctx, got); err != nil {
		t.Fatal(err)
	}
	if jobs, err := st.Candidates(ctx, QueueNew, 10, 0); err != nil || len(jobs) != 1 {
		t.Errorf("a released file is not a candidate: %+v, %v", jobs, err)
	}

	// A file handed out 8 times without a result is stuck.
	for range 8 {
		if _, err := st.Lease(ctx, got, hour); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE queue SET retry_at = now() - interval '1 second'`); err != nil {
			t.Fatal(err)
		}
	}
	if jobs, err := st.Candidates(ctx, QueueNew, 10, 0); err != nil || len(jobs) != 0 {
		t.Errorf("a stuck file is still a candidate: %+v, %v", jobs, err)
	}
	if depths, stuck, err := st.Depths(ctx); err != nil || stuck != 1 || depths[QueueBigArchive] != 1 {
		t.Errorf("depths %v, stuck %d, %v", depths, stuck, err)
	}
	if ok, err := st.Rescan(ctx, small, time.Now()); err != nil || !ok {
		t.Fatalf("rescan of a stuck file: %v, %v", ok, err)
	}
	if jobs, err := st.Candidates(ctx, QueueRequested, 10, 0); err != nil || len(jobs) != 1 {
		t.Errorf("a requested rescan of a stuck file is not a candidate: %+v, %v", jobs, err)
	}
}

func TestQueueSettledByResults(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	pkg, script, other := digestOf("package bytes"), digestOf("script bytes"), digestOf("another package")

	// Another archive holds the same script, and was judged benign.
	holder := &result{
		header: r.header,
		files: []map[string]any{
			{
				"sha256": hexOf(other), "size": 9, "type": "npm",
				"verdict":  map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
				"contents": map[string]any{"children": []int{1}, "paths": []string{"lib/install.js"}},
			},
			{
				"sha256": hexOf(script), "size": 300, "type": "javascript",
				"verdict": map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
			},
		},
	}
	holder.write(ctx, t, st)
	r.files[0]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	r.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	for _, f := range r.files {
		delete(f, "floor")
	}
	r.write(ctx, t, st)
	place(ctx, t, st, pkg, "pool/pkg.tgz")
	place(ctx, t, st, other, "pool/other.tgz")
	enqueue(ctx, t, st, QueueRequested, pkg)

	t.Run("a scan that fails for a passing reason backs off", func(t *testing.T) {
		failed := &result{header: strings.Replace(r.header, `"files":2`, `"files":1`, 1), files: []map[string]any{{
			"sha256": hexOf(pkg), "size": 4000, "type": "npm",
			"verdict": map[string]any{"outcome": "error", "error": "too many open files"},
		}}}
		failed.write(ctx, t, st)
		var note string
		var later bool
		if err := st.pool.QueryRow(ctx, `SELECT note, retry_at > now() + interval '1 hour' FROM queue q
			JOIN samples s ON s.id = q.sample_id WHERE s.sha256 = $1`, pkg).Scan(&note, &later); err != nil ||
			note != "too many open files" || !later {
			t.Errorf("note %q, backed off %v, %v", note, later, err)
		}
	})

	t.Run("a script that got worse queues the other archive holding it", func(t *testing.T) {
		r.header = strings.NewReplacer(`"ruleset":"r1"`, `"ruleset":"r2"`, "T15:00:00Z", "T16:00:00Z").Replace(r.header)
		r.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12}
		got := r.write(ctx, t, st)
		if got.Requeued != 1 {
			t.Errorf("stats %+v, want one archive requeued", got)
		}
		p := priorities(ctx, t, st)
		if _, ok := p[hexOf(pkg)]; ok {
			t.Errorf("queue %v: the archive just scanned is still owed a scan", p)
		}
		if p[hexOf(other)] != QueueRepair {
			t.Errorf("queue %v: the other archive should be queued for repair", p)
		}
	})
}

func TestQueueRescan(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	archive().write(ctx, t, st) // scanned at 15:00
	pkg, fresh := digestOf("package bytes"), digestOf("never scanned")
	before, after := time.Date(2026, 11, 12, 14, 0, 0, 0, time.UTC), time.Date(2026, 11, 12, 16, 0, 0, 0, time.UTC)
	rescan := func(sha []byte, since time.Time) bool {
		t.Helper()
		queued, err := st.Rescan(ctx, sha, since)
		if err != nil {
			t.Fatal(err)
		}
		return queued
	}

	if rescan(digestOf("no such file"), after) {
		t.Error("queued a file hopper has never seen")
	}
	if rescan(pkg, after) {
		t.Error("queued a file with nowhere to read it from")
	}
	place(ctx, t, st, pkg, "pool/pkg.tgz")
	if rescan(pkg, before) {
		t.Error("queued a file scanned since the cutoff")
	}
	if !rescan(pkg, after) {
		t.Error("did not queue a file last scanned before the cutoff")
	}
	if !rescan(pkg, before) {
		t.Error("refused a second request for a scan still owed")
	}

	ingest(ctx, t, st, QueueNew, Arrival{SHA256: fresh, Size: 100, Path: "pool/fresh"})
	if !rescan(fresh, before) {
		t.Error("did not raise a file waiting on its first scan")
	}
	want := map[string]Priority{hexOf(pkg): QueueRequested, hexOf(fresh): QueueRequested}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("priorities %v, want %v", got, want)
	}
}

func TestQueueSweepStale(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.write(ctx, t, st)
	pkg := digestOf("package bytes")
	place(ctx, t, st, pkg, "pool/pkg.tgz")

	// The archive was scanned at 15:00 on 2026-11-12.
	next, queued, err := st.SweepStale(ctx, Cursor{}, time.Date(2026, 11, 12, 14, 0, 0, 0, time.UTC), 1)
	if err != nil || queued != 0 || next != (Cursor{}) {
		t.Fatalf("sweep for files scanned before the scan: next %+v, queued %d, %v; want nothing and the pass over", next, queued, err)
	}
	var total int64
	for after := (Cursor{}); ; {
		n, q, err := st.SweepStale(ctx, after, time.Date(2026, 11, 12, 16, 0, 0, 0, time.UTC), 1)
		if err != nil {
			t.Fatal(err)
		}
		total += q
		if after = n; after == (Cursor{}) {
			break
		}
	}
	p := priorities(ctx, t, st)
	if total != 1 || p[hexOf(pkg)] != QueueStale || len(p) != 1 {
		t.Errorf("queued %d, queue %v: want the file on disk alone, as stale", total, p)
	}

	sweep := func(before time.Time) int64 {
		t.Helper()
		if _, err := st.pool.Exec(ctx, `DELETE FROM queue`); err != nil {
			t.Fatal(err)
		}
		_, queued, err := st.SweepStale(ctx, Cursor{}, before, 100)
		if err != nil {
			t.Fatal(err)
		}
		return queued
	}
	at := func(hour int) time.Time { return time.Date(2026, 11, 12, hour, 0, 0, 0, time.UTC) }
	stamp := func(r *result, hour int) {
		r.header = strings.Replace(archive().header, `"at":"2026-11-12T15:00:00Z"`, fmt.Sprintf(`"at":"2026-11-12T%02d:00:00Z"`, hour), 1)
	}

	t.Run("a rescan that finds the same thing still counts as a scan", func(t *testing.T) {
		stamp(r, 17)
		if got := r.write(ctx, t, st); got.Verdicts != 0 || got.Stamped != 1 {
			t.Errorf("stats %+v, want no verdict written and the archive's scan recorded", got)
		}
		if n := sweep(at(16)); n != 0 {
			t.Errorf("queued %d: a file rescanned at 17:00 is not older than 16:00", n)
		}
		if n := sweep(at(18)); n != 1 {
			t.Errorf("queued %d, want the file once the cutoff passes its last scan", n)
		}
	})

	t.Run("a rescan that fails still counts as one", func(t *testing.T) {
		failed := &result{files: []map[string]any{{
			"sha256": hexOf(pkg), "size": 4000, "type": "npm", "verdict": map[string]any{"outcome": "timeout", "error": "60s"},
		}}}
		stamp(failed, 19)
		failed.header = strings.Replace(failed.header, `"files":2`, `"files":1`, 1)
		failed.write(ctx, t, st)
		if n := sweep(at(18)); n != 0 {
			t.Errorf("queued %d: a file tried at 19:00 would be handed out on every pass", n)
		}
		rec, err := st.BySHA256(ctx, pkg)
		if err != nil || rec.Class != "hostile" {
			t.Errorf("record %+v, %v: the failed rescan replaced the verdict", rec, err)
		}
		if !rec.ScannedAt.Equal(at(19)) || rec.Ruleset != "r1" {
			t.Errorf("record scanned %v under %q, want 19:00 under r1: tried since, confirmed under the ruleset that worked", rec.ScannedAt, rec.Ruleset)
		}
	})

	t.Run("an upload older than the recorded scan does not move it back", func(t *testing.T) {
		stamp(r, 12)
		if got := r.write(ctx, t, st); got.Stamped != 0 {
			t.Errorf("stats %+v, want the scans row left alone", got)
		}
		if rec, err := st.BySHA256(ctx, pkg); err != nil || !rec.ScannedAt.Equal(at(19)) {
			t.Errorf("record %+v, %v: want last scanned 19:00", rec, err)
		}
	})
}
