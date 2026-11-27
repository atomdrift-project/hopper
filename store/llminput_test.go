package store

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// An input is kept for a known file, replaced by the next, refused for a
// file hopper does not know, and not kept for a file an LLM has described.
func TestLLMInputRoundTrip(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	release(ctx, t, st, "payload", "", "", "")
	release(ctx, t, st, "described", "", "", "")
	scanAt(ctx, t, st, "described", "hostile", time.Now().Add(-time.Minute), true)

	if _, err := st.LLMInput(ctx, digestOf("payload")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before any upload: %v, want ErrNotFound", err)
	}
	for _, input := range [][]byte{[]byte("first"), []byte("second, longer")} {
		known, stored, err := st.SetLLMInput(ctx, digestOf("payload"), input)
		if err != nil || !known || !stored {
			t.Fatalf("set %q: known %v, stored %v, %v", input, known, stored, err)
		}
		got, err := st.LLMInput(ctx, digestOf("payload"))
		if err != nil || !bytes.Equal(got, input) {
			t.Errorf("read back %q, %v; want %q", got, err, input)
		}
	}
	if known, stored, err := st.SetLLMInput(ctx, digestOf("nobody"), []byte("x")); err != nil || known || stored {
		t.Errorf("unknown file: known %v, stored %v, %v; want neither", known, stored, err)
	}
	if known, stored, err := st.SetLLMInput(ctx, digestOf("described"), []byte("x")); err != nil || !known || stored {
		t.Errorf("described file: known %v, stored %v, %v; want known and not stored", known, stored, err)
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM llm_inputs`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("%d inputs stored, %v; want the one file's", rows, err)
	}
}

// Files to describe whose input hopper holds say so and are handed out
// before the others of the level, whatever their queue order; the probe is
// left to that level.
func TestLLMInputCandidates(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	for _, name := range []string{"older", "newer", "first scan"} {
		release(ctx, t, st, name, "", "", "")
	}
	if _, err := st.pool.Exec(ctx, `UPDATE queue SET priority = $1, queued_at = now() - make_interval(hours => 1000 - s.id::int)
		FROM samples s WHERE s.id = queue.sample_id AND s.sha256 = ANY($2)`,
		int16(QueueDescribe), [][]byte{digestOf("older"), digestOf("newer")}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"newer", "first scan"} {
		if _, _, err := st.SetLLMInput(ctx, digestOf(name), []byte("input")); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := st.Candidates(ctx, QueueDescribe, 10, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 || jobs[0].SHA256 != sum("newer") || !jobs[0].HasLLMInput ||
		jobs[1].SHA256 != sum("older") || jobs[1].HasLLMInput {
		t.Errorf("describe candidates %+v, want newer (with its input) before older (without)", jobs)
	}
	jobs, err = st.Candidates(ctx, QueueNew, 10, 0, nil)
	if err != nil || len(jobs) != 1 || jobs[0].HasLLMInput {
		t.Errorf("first-scan candidates %+v, %v; want one, not read for an input", jobs, err)
	}
}

// An input is deleted when a result stores the LLM's description of its
// file, and kept by a result without one; the sweep deletes inputs older
// than a week.
func TestLLMInputRetention(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	now := time.Now().Add(-time.Minute)
	for _, name := range []string{"payload", "old", "kept"} {
		release(ctx, t, st, name, "", "", "")
		scanAt(ctx, t, st, name, "hostile", now, false)
		if _, _, err := st.SetLLMInput(ctx, digestOf(name), []byte("input")); err != nil {
			t.Fatal(err)
		}
	}
	has := func(name string) bool {
		t.Helper()
		_, err := st.LLMInput(ctx, digestOf(name))
		if err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}

	if got := scanAt(ctx, t, st, "payload", "hostile", now.Add(time.Second), false); got.LLMInputDropped || !has("payload") {
		t.Errorf("a rescan without an LLM dropped the input (stats %+v)", got)
	}
	if got := scanAt(ctx, t, st, "payload", "hostile", now.Add(time.Second), true); !got.LLMInputDropped || has("payload") {
		t.Errorf("the LLM's amendment kept the input (stats %+v)", got)
	}

	if _, err := st.pool.Exec(ctx, `UPDATE llm_inputs SET stored_at = now() - interval '7 days 1 minute'
		WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`, digestOf("old")); err != nil {
		t.Fatal(err)
	}
	if _, inputs, err := st.ExpireDescribe(ctx); err != nil || inputs != 1 {
		t.Errorf("expiry deleted %d inputs, %v; want 1", inputs, err)
	}
	if has("old") || !has("kept") {
		t.Errorf("after expiry: old held %v, kept held %v; want only the week-old one gone", has("old"), has("kept"))
	}
}

// A failed LLM call is stored as an llm verdict with outcome error. It
// describes nothing: the file stays owed a description, an input uploaded for
// the retry is kept, and the failed amendment does not delete one. Before
// 2026-11-27 any llm row counted, so one failed call left a file with no
// description for good.
func TestFailedLLMCallLeavesFileOwed(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	release(ctx, t, st, "failed", "", "", "")
	scanAt(ctx, t, st, "failed", "hostile", time.Now().Add(-2*time.Hour), true)
	if _, err := st.pool.Exec(ctx, `UPDATE verdicts SET outcome = 'error'
		WHERE scanner_id = $1 AND sample_id = (SELECT id FROM samples WHERE sha256 = $2)`,
		jurors["llm"], digestOf("failed")); err != nil {
		t.Fatal(err)
	}

	var owed bool
	if err := st.pool.QueryRow(ctx, `WITH c AS (SELECT id AS sample_id FROM samples WHERE sha256 = $1)
		SELECT EXISTS (SELECT 1 FROM c WHERE `+owedDescription+`)`, digestOf("failed")).Scan(&owed); err != nil {
		t.Fatal(err)
	}
	if !owed {
		t.Error("a file whose only llm verdict is a failed call is not owed a description")
	}
	if known, stored, err := st.SetLLMInput(ctx, digestOf("failed"), []byte("retry")); err != nil || !known || !stored {
		t.Fatalf("input after a failed call: known %v, stored %v, %v; want stored", known, stored, err)
	}
	if _, err := st.LLMInput(ctx, digestOf("failed")); err != nil {
		t.Errorf("input after a failed call not readable: %v", err)
	}
}
