package store

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// scanAt uploads a scan of the named bytes alone made at at, with the given
// class, described by an LLM or not.
func scanAt(ctx context.Context, t *testing.T, st *Store, bytes, class string, at time.Time, described bool) Stats {
	t.Helper()
	root := map[string]any{
		"sha256": sum(bytes), "size": 100, "type": "npm",
		"verdict": map[string]any{"outcome": "ok", "class": class, "fires_at": 12},
	}
	if described {
		root["llm"] = map[string]any{"class": class, "conf": 0.9, "reason": "Downloads and runs a binary."}
	}
	r := &result{
		header: fmt.Sprintf(`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":%q,"ms":40},"files":1}`,
			at.UTC().Format(time.RFC3339)),
		files: []map[string]any{root},
	}
	return r.write(ctx, t, st)
}

// describing returns the files queued to be described and whether each may
// be handed out now.
func describing(ctx context.Context, t *testing.T, st *Store) map[string]bool {
	t.Helper()
	rows, err := st.pool.Query(ctx, `SELECT encode(s.sha256, 'hex'), q.retry_at IS NULL OR q.retry_at <= now()
		FROM queue q JOIN samples s ON s.id = q.sample_id WHERE q.priority = $1`, int16(QueueDescribe))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var sha string
		var due bool
		if err := rows.Scan(&sha, &due); err != nil {
			t.Fatal(err)
		}
		out[sha] = due
	}
	return out
}

// A result that leaves a flagged file undescribed queues it to be described
// once the LLM's amendment has had time to come; one described, or benign,
// does not, and the amendment takes the row away.
func TestDescribeOnResult(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	now := time.Now().Add(-time.Minute)
	for _, name := range []string{"hostile", "suspicious", "described", "benign", "nowhere"} {
		release(ctx, t, st, name, "", "", "")
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM locations WHERE path = 'pool/nowhere'`); err != nil {
		t.Fatal(err)
	}
	if got := scanAt(ctx, t, st, "hostile", "hostile", now, false); got.Described != 1 {
		t.Errorf("hostile without a description: described %d, want 1", got.Described)
	}
	scanAt(ctx, t, st, "suspicious", "suspicious", now, false)
	scanAt(ctx, t, st, "described", "hostile", now, true)
	scanAt(ctx, t, st, "benign", "benign", now, false)
	scanAt(ctx, t, st, "nowhere", "hostile", now, false)
	want := map[string]bool{hexOf(digestOf("hostile")): false, hexOf(digestOf("suspicious")): false}
	if got := describing(ctx, t, st); !maps.Equal(got, want) {
		t.Fatalf("queued to describe %v, want %v (none due yet)", got, want)
	}
	if jobs, err := st.Candidates(ctx, QueueDescribe, 10, 0, nil); err != nil || len(jobs) != 0 {
		t.Errorf("candidates %+v, %v: none is due before describeGrace", jobs, err)
	}

	// The LLM's amendment of the same scan.
	scanAt(ctx, t, st, "hostile", "hostile", now, true)
	delete(want, hexOf(digestOf("hostile")))
	if got := describing(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("after the amendment: %v, want %v", got, want)
	}
}

// The sweep queues the flagged, undescribed files of the last week's scans
// that are past describeGrace, at most once a week each, and drops queued
// rows no longer owed a description.
func TestSweepDescribe(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	ago := func(d time.Duration) time.Time { return time.Now().Add(-d) }
	for name, at := range map[string]time.Time{
		"recent": ago(48 * time.Hour), "old": ago(8 * 24 * time.Hour), "fresh": ago(10 * time.Minute),
		"expiring": ago(48 * time.Hour), "described later": ago(48 * time.Hour),
	} {
		release(ctx, t, st, name, "", "", "")
		scanAt(ctx, t, st, name, "hostile", at, false)
	}
	// As if they had been scanned before the describe level existed.
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue; DELETE FROM llm_attempts`); err != nil {
		t.Fatal(err)
	}
	sweep := func() (queued, dropped int64) {
		t.Helper()
		dropped, _, err := st.ExpireDescribe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var after Cursor
		for {
			next, q, err := st.SweepDescribe(ctx, after, 2) // pages of 2: the cursor carries on
			if err != nil {
				t.Fatal(err)
			}
			queued += q
			if after = next; after == (Cursor{}) {
				return queued, dropped
			}
		}
	}
	if q, d := sweep(); q != 3 || d != 0 {
		t.Errorf("first sweep queued %d, dropped %d; want 3, 0", q, d)
	}
	want := map[string]bool{
		hexOf(digestOf("recent")): true, hexOf(digestOf("expiring")): true, hexOf(digestOf("described later")): true,
	}
	if got := describing(ctx, t, st); !maps.Equal(got, want) {
		t.Fatalf("queued to describe %v, want %v", got, want)
	}

	// A row whose scan has aged past the week, and one described since,
	// leave the level.
	if _, err := st.pool.Exec(ctx, `UPDATE scans SET scanned_at = now() - interval '8 days'
		WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`, digestOf("expiring")); err != nil {
		t.Fatal(err)
	}
	scanAt(ctx, t, st, "described later", "hostile", ago(47*time.Hour), true)
	if _, err := st.pool.Exec(ctx, `INSERT INTO queue (sample_id, priority)
		SELECT id, $2 FROM samples WHERE sha256 = $1`, digestOf("described later"), int16(QueueDescribe)); err != nil {
		t.Fatal(err)
	}
	if q, d := sweep(); q != 0 || d != 2 {
		t.Errorf("second sweep queued %d, dropped %d; want 0, 2", q, d)
	}
	delete(want, hexOf(digestOf("expiring")))
	delete(want, hexOf(digestOf("described later")))
	if got := describing(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("after expiry: %v, want %v", got, want)
	}

	// Handed out and back undescribed: not queued again this week.
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue`); err != nil {
		t.Fatal(err)
	}
	if q, _ := sweep(); q != 0 {
		t.Errorf("a file queued to describe this week was queued again: %d", q)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE llm_attempts SET at = now() - interval '8 days'`); err != nil {
		t.Fatal(err)
	}
	if q, _ := sweep(); q != 1 {
		t.Errorf("a week on, queued %d, want the one file again", q)
	}
}

// A rescan by a worker without an LLM keeps the description an earlier scan
// stored, and is not queued to be described again; a rescan that carries the
// LLM's opinion replaces it; one that finds the file benign drops it, since
// what the LLM wrote explains a verdict the file no longer has.
func TestRescanKeepsDescription(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	release(ctx, t, st, "payload", "", "", "")
	start := time.Now().Add(-time.Hour)
	scan := func(minute int, class, reason string) Stats {
		t.Helper()
		fires := 12
		if class == "benign" {
			fires = -1
		}
		root := map[string]any{
			"sha256": sum("payload"), "size": 100, "type": "npm",
			"verdict": map[string]any{"outcome": "ok", "class": class, "fires_at": fires},
			"floor":   map[string]any{"class": class, "fires_at": fires},
		}
		if reason != "" {
			root["llm"] = map[string]any{"class": class, "conf": 0.9, "reason": reason}
		}
		r := &result{
			header: fmt.Sprintf(`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":%q,"ms":40},"files":1}`,
				start.Add(time.Duration(minute)*time.Minute).UTC().Format(time.RFC3339)),
			files: []map[string]any{root},
		}
		return r.write(ctx, t, st)
	}
	description := func() string {
		t.Helper()
		var reason string
		err := st.pool.QueryRow(ctx, `SELECT coalesce((SELECT v.summary->>'reason' FROM verdicts v
				JOIN samples s ON s.id = v.sample_id WHERE s.sha256 = $1 AND v.scanner_id = $2), '')`,
			digestOf("payload"), jurors["llm"]).Scan(&reason)
		if err != nil {
			t.Fatal(err)
		}
		return reason
	}

	scan(0, "hostile", "Downloads and runs a binary.")
	for _, class := range []string{"hostile", "suspicious"} {
		got := scan(map[string]int{"hostile": 1, "suspicious": 2}[class], class, "")
		if got.JurorsRemoved != 0 || got.Described != 0 {
			t.Errorf("%s rescan without an LLM: stats %+v, want nothing removed and nothing to describe", class, got)
		}
		if d := description(); d != "Downloads and runs a binary." {
			t.Errorf("%s rescan without an LLM: description %q, want the stored one kept", class, d)
		}
	}

	scan(3, "hostile", "Steals npm tokens.")
	if d := description(); d != "Steals npm tokens." {
		t.Errorf("rescan with an LLM: description %q, want it replaced", d)
	}

	if got := scan(4, "benign", ""); got.JurorsRemoved != 1 {
		t.Errorf("benign rescan: stats %+v, want the description removed", got)
	}
	if d := description(); d != "" {
		t.Errorf("benign rescan: description %q kept, want none", d)
	}
}

// gatedScan uploads a scan of the named bytes alone made at at, with the
// given class and, unless empty, what the LLM gate decided (llm_admission)
// and the LLM's opinion: "ok" for a description, "error" for a failed call.
func gatedScan(ctx context.Context, t *testing.T, st *Store, bytes, class, admission, llm string, at time.Time) Stats {
	t.Helper()
	verdict := map[string]any{"outcome": "ok", "class": class, "fires_at": 12}
	if admission != "" {
		verdict["llm_admission"] = admission
	}
	root := map[string]any{"sha256": sum(bytes), "size": 100, "type": "npm", "verdict": verdict}
	switch llm {
	case "ok":
		root["llm"] = map[string]any{"class": class, "conf": 0.9, "reason": "Reads ~/.npmrc and posts it."}
	case "error":
		root["llm"] = map[string]any{"outcome": "error", "error": "endpoint timed out", "model": "test-8B"}
	}
	r := &result{
		header: fmt.Sprintf(`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":%q,"ms":40},"files":1}`,
			at.UTC().Format(time.RFC3339)),
		files: []map[string]any{root},
	}
	return r.write(ctx, t, st)
}

// owed reports whether the file with the named bytes is owed a description.
func owed(ctx context.Context, t *testing.T, st *Store, bytes string) bool {
	t.Helper()
	var owed bool
	if err := st.pool.QueryRow(ctx, `WITH c AS (SELECT id AS sample_id FROM samples WHERE sha256 = $1)
		SELECT EXISTS (SELECT 1 FROM c WHERE `+owedDescription+`)`, digestOf(bytes)).Scan(&owed); err != nil {
		t.Fatal(err)
	}
	return owed
}

// A file is owed a description when scan's LLM gate admitted it, at either
// tier and whatever its class, and no LLM described it: what the gate says,
// not atomscan's class, decides. A scan that does not say (an older worker)
// falls back to the rule before: atomscan calls it hostile or suspicious, as
// does one that says a word hopper does not know. A failed LLM call
// describes nothing.
func TestDescribeFollowsTheGate(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	now := time.Now().Add(-time.Minute)
	for _, c := range []struct {
		name, class, admission, llm string
		owed                        bool
	}{
		{"required", "hostile", "required", "", true},
		{"required benign", "benign", "required", "", true},
		{"optional benign", "benign", "optional", "", true},
		{"not admitted", "benign", "none", "", false},
		{"not admitted suspicious", "suspicious", "none", "", false},
		{"unknown hostile", "hostile", "", "", true},
		{"unknown suspicious", "suspicious", "", "", true},
		{"unknown benign", "benign", "", "", false},
		{"unknown word hostile", "hostile", "maybe", "", true},
		{"unknown word benign", "benign", "maybe", "", false},
		{"required described", "hostile", "required", "ok", false},
		{"optional described", "benign", "optional", "ok", false},
		{"required failed", "hostile", "required", "error", true},
		{"optional failed", "benign", "optional", "error", true},
	} {
		release(ctx, t, st, c.name, "", "", "")
		got := gatedScan(ctx, t, st, c.name, c.class, c.admission, c.llm, now)
		if want := map[bool]int64{true: 1}[c.owed]; got.Described != want {
			t.Errorf("%s: queued to describe %d, want %d", c.name, got.Described, want)
		}
		if o := owed(ctx, t, st, c.name); o != c.owed {
			t.Errorf("%s: owed %v, want %v", c.name, o, c.owed)
		}
	}

	// The gate's word is the last scan's: a rescan that says nothing puts
	// the file back under the older rule, and one the gate turns away
	// leaves it owed nothing.
	gatedScan(ctx, t, st, "optional benign", "benign", "", "", now.Add(time.Second))
	if owed(ctx, t, st, "optional benign") {
		t.Error("a benign rescan that does not say is owed a description")
	}
	gatedScan(ctx, t, st, "required", "hostile", "none", "", now.Add(time.Second))
	if owed(ctx, t, st, "required") {
		t.Error("a rescan the gate turned away is still owed a description")
	}
	if _, _, err := st.ExpireDescribe(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, name := range []string{
		"required benign", "unknown hostile", "unknown suspicious", "unknown word hostile", "required failed", "optional failed",
	} {
		want[hexOf(digestOf(name))] = false
	}
	if got := describing(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("queued to describe %v, want %v", got, want)
	}
}

// The sweep finds an admitted file the floor and the model call benign,
// whose scan is not flagged, through scans_describable; and hands out, after
// files whose LLM input is held, the required admissions before the optional.
func TestSweepDescribeFollowsTheGate(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	at := time.Now().Add(-2 * time.Hour)
	for name, admission := range map[string]string{
		"optional": "optional", "required": "required", "held": "optional", "none": "none",
	} {
		release(ctx, t, st, name, "", "", "")
		gatedScan(ctx, t, st, name, "benign", admission, "", at)
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue; DELETE FROM llm_attempts`); err != nil {
		t.Fatal(err)
	}
	var flagged int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM scans WHERE flagged`).Scan(&flagged); err != nil || flagged != 0 {
		t.Fatalf("%d flagged scans, %v; want none", flagged, err)
	}
	next, queued, err := st.SweepDescribe(ctx, Cursor{}, 10)
	if err != nil || queued != 3 || next != (Cursor{}) {
		t.Fatalf("sweep queued %d, next %v, %v; want the three admitted, and the end", queued, next, err)
	}
	if known, stored, err := st.SetLLMInput(ctx, digestOf("held"), []byte("input")); err != nil || !known || !stored {
		t.Fatalf("input: known %v, stored %v, %v", known, stored, err)
	}
	// Queued first, so only the tier puts the required file ahead of it.
	if _, err := st.pool.Exec(ctx, `UPDATE queue SET queued_at = queued_at - interval '1 hour'
		WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`, digestOf("optional")); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.Candidates(ctx, QueueDescribe, 10, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, j := range jobs {
		order = append(order, j.SHA256)
	}
	if want := []string{hexOf(digestOf("held")), hexOf(digestOf("required")), hexOf(digestOf("optional"))}; !slices.Equal(order, want) {
		t.Errorf("handed out %v, want %v (held input, required, optional)", order, want)
	}

	// The sweep's page is read through the index, whatever the table holds.
	var plan []string
	err = pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `EXPLAIN SELECT sample_id, scanned_at FROM scans
			WHERE `+describable+` AND (scanned_at, sample_id) > ($1, $2)
			ORDER BY scanned_at, sample_id LIMIT 10`, time.Time{}, int64(0))
		if err != nil {
			return err
		}
		plan, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), "scans_describable") {
		t.Errorf("the sweep's page does not read scans_describable:\n%s", strings.Join(plan, "\n"))
	}
}

// The files prism publishes are described first and retried within hours: a
// hostile file of the last 72 hours (Fallout), and a suspicious-or-worse file
// a malicious claim names, of the last 24 hours (Malware). Older ones, and a
// fresh suspicious file nobody accuses, wait their turn and a week between
// attempts.
func TestDescribeUrgentBands(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	scanned := time.Now().Add(-2 * time.Hour) // past describeGrace
	for name, file := range map[string]struct {
		class string
		age   time.Duration
	}{
		"fresh hostile":   {"hostile", time.Hour},
		"old hostile":     {"hostile", 5 * 24 * time.Hour},
		"fresh accused":   {"suspicious", time.Hour},
		"day-old accused": {"suspicious", 30 * time.Hour},
		"fresh unaccused": {"suspicious", time.Hour},
	} {
		release(ctx, t, st, name, "", "", "")
		scanAt(ctx, t, st, name, file.class, scanned, false)
		if _, err := st.pool.Exec(ctx, `UPDATE samples SET created_at = now() - $2::interval WHERE sha256 = $1`,
			digestOf(name), file.age); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"fresh accused", "day-old accused"} {
		claim(ctx, t, st, "osm", hexOf(digestOf(name)), "", "malicious")
	}
	urgent := []string{hexOf(digestOf("fresh hostile")), hexOf(digestOf("fresh accused"))}
	sweep := func() int64 {
		t.Helper()
		var queued int64
		var after Cursor
		for {
			next, q, err := st.SweepDescribe(ctx, after, 10)
			if err != nil {
				t.Fatal(err)
			}
			queued += q
			if after = next; after == (Cursor{}) {
				return queued
			}
		}
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue; DELETE FROM llm_attempts`); err != nil {
		t.Fatal(err)
	}
	if q := sweep(); q != 5 {
		t.Fatalf("sweep queued %d, want all 5", q)
	}
	jobs, err := st.Candidates(ctx, QueueDescribe, 10, 0, nil)
	if err != nil || len(jobs) != 5 {
		t.Fatalf("candidates %+v, %v", jobs, err)
	}
	first := []string{jobs[0].SHA256, jobs[1].SHA256}
	slices.Sort(first)
	slices.Sort(urgent)
	if !slices.Equal(first, urgent) {
		t.Errorf("first two to describe %v, want the urgent %v", first, urgent)
	}

	// Handed out and back undescribed, four hours ago: only the urgent ones
	// are queued again.
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue; UPDATE llm_attempts SET at = now() - interval '4 hours'`); err != nil {
		t.Fatal(err)
	}
	if q := sweep(); q != 2 {
		t.Errorf("retry sweep queued %d, want the 2 urgent files", q)
	}
	got := slices.Sorted(maps.Keys(describing(ctx, t, st)))
	if !slices.Equal(got, urgent) {
		t.Errorf("queued again %v, want %v", got, urgent)
	}
}
