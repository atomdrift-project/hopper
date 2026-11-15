package store

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

// packed is a UPX-packed executable holding one member, its unpacked
// payload, as forager's bazaar downloads come: the payload is also on disk
// and scanned on its own, which reads more of it than unpacking it inside
// the executable's scan does. Seen in the migration rehearsal
// (bc2613fe5b76…, inside 48c182dbd3d2…): the payload's own scan, hostile at
// L12 with findings and an LLM reason, and the executable's line for it,
// hostile at L25 with neither, stored at the same moment by two writers.
func packed() (own, archive *result) {
	payload := sum("payload bytes")
	own = &result{
		header:  `{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":1}`,
		reports: []string{`{"traits":[{"id":"c2::keylogger","crit":5}]}`},
	}
	own.files = []map[string]any{{
		"sha256": payload, "size": 300, "type": "pe", "report": sum(own.reports[0]),
		"verdict": map[string]any{
			"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "llm",
			"reason": "Records keystrokes and sends them out.",
			"top":    []map[string]any{{"id": "c2::keylogger", "crit": 5}},
		},
		"floor": map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
		"llm":   map[string]any{"class": "hostile", "conf": 0.9, "reason": "Records keystrokes and sends them out."},
	}}
	archive = &result{
		header:  `{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w2","at":"2026-11-12T16:00:00Z","ms":40},"files":2}`,
		reports: []string{`{"traits":[{"id":"pack::upx","crit":2}]}`, `{"traits":[]}`},
	}
	archive.files = []map[string]any{
		{
			"sha256": sum("packed bytes"), "size": 200, "type": "pe", "report": sum(archive.reports[0]),
			"verdict":  map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 25, "by": "floor", "in": payload},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"upx@0"}},
		},
		{
			"sha256": payload, "size": 300, "type": "pe", "report": sum(archive.reports[1]),
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 25},
		},
	}
	return own, archive
}

// interleave stores first and second so that first reads what is stored,
// second is stored whole, and only then does first go on to write.
func interleave(ctx context.Context, t *testing.T, st *Store, first, second *result) {
	t.Helper()
	// Both files exist with their types and sizes already, as ingest leaves
	// them, so neither write inserts or retypes a row the other waits on.
	if _, err := st.pool.Exec(ctx, `INSERT INTO samples (sha256, size_bytes, file_type)
		VALUES ($1, 300, 'pe'), ($2, 200, 'pe')`, digestOf("payload bytes"), digestOf("packed bytes")); err != nil {
		t.Fatal(err)
	}
	var paused atomic.Bool
	read, resume := make(chan struct{}), make(chan struct{})
	st.afterRead = func() {
		if paused.CompareAndSwap(false, true) {
			close(read)
			<-resume
		}
	}
	done := make(chan Stats)
	go func() { done <- first.write(ctx, t, st) }()
	<-read
	second.write(ctx, t, st)
	close(resume)
	<-done
	st.afterRead = nil
}

// payloadVerdict is the payload's atomscan level and reason, and whether its
// llm row is stored.
func payloadVerdict(ctx context.Context, t *testing.T, st *Store) (firesAt int, reason string, llm bool) {
	t.Helper()
	if err := st.pool.QueryRow(ctx, `SELECT v.fires_at, coalesce(v.summary->>'reason', ''),
			EXISTS (SELECT 1 FROM verdicts l WHERE l.sample_id = s.id AND l.scanner_id = $2)
		FROM samples s JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $3
		WHERE s.sha256 = $1`, digestOf("payload bytes"), jurors["llm"], atomscan).Scan(&firesAt, &reason, &llm); err != nil {
		t.Fatal(err)
	}
	return firesAt, reason, llm
}

// A file's own scan and an archive's thinner line for it, stored at once,
// keep the own scan's verdict whichever reads first: the writer decides
// what to hold back from rows another writer may be changing, so it locks
// the files it will write and decides again (writer.lock). Without that,
// each order lost the richer verdict: a stale read let the thin line
// replace it, or kept the own scan from reclaiming.
func TestWriteRaceKeepsRicherVerdict(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ownFirst bool
	}{
		{"own scan reads first, the archive's line commits, then the own scan writes", true},
		{"the archive's line reads first, the own scan commits, then the line writes", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := open(t)
			ctx := t.Context()
			own, archive := packed()
			if tc.ownFirst {
				interleave(ctx, t, st, own, archive)
			} else {
				interleave(ctx, t, st, archive, own)
			}
			firesAt, reason, llm := payloadVerdict(ctx, t, st)
			if firesAt != 12 || !strings.Contains(reason, "keystrokes") || !llm {
				t.Errorf("payload at L%d, reason %q, llm row %v: want the own scan's L12, its reason and its llm row", firesAt, reason, llm)
			}
		})
	}
}
