package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/scanresult"
)

// at returns r with its scan stamped at hour h of the fixture's day.
func at(r *result, h int) *result {
	r.header = strings.Replace(r.header, "T15:00:00Z", fmt.Sprintf("T%02d:00:00Z", h), 1)
	return r
}

// atomscanClass is atomscan's stored class for the file with these bytes.
func atomscanClass(ctx context.Context, t *testing.T, st *Store, bytes string) string {
	t.Helper()
	var class string
	err := st.pool.QueryRow(ctx, `SELECT coalesce(v.class::text, '') FROM verdicts v JOIN samples s ON s.id = v.sample_id
		WHERE s.sha256 = $1 AND v.scanner_id = $2`, digestOf(bytes), atomscan).Scan(&class)
	if err != nil {
		t.Fatal(err)
	}
	return class
}

// A result older than the artifact's recorded scan arrives after it, as a
// retried upload does: it is stale, and changes nothing.
func TestWriteLate(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	at(archive(), 16).write(ctx, t, st)

	old := at(archive(), 15)
	old.files[0]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	if got := old.write(ctx, t, st); !got.Late || got.Changed() {
		t.Errorf("stats %+v: want a late result that changed nothing", got)
	}
	if class := atomscanClass(ctx, t, st, "package bytes"); class != "hostile" {
		t.Errorf("class %q: an older scan replaced a newer verdict", class)
	}
}

// A member shared by two archives keeps the opinion formed last, whichever
// archive's result is stored last.
func TestWriteKeepsNewerOpinion(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	at(archive(), 16).write(ctx, t, st) // the script, hostile, formed at 16:00

	other := at(archive(), 15)
	other.files[0]["sha256"] = sum("another package")
	other.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	delete(other.files[1], "floor")
	other.write(ctx, t, st)
	if class := atomscanClass(ctx, t, st, "script bytes"); class != "hostile" {
		t.Errorf("class %q: an opinion formed at 15:00 replaced one formed at 16:00", class)
	}
}

// A nested archive's member list follows the newest list stated for it,
// whichever result is stored last, and not the newest opinion of the archive:
// a scan that judges it without listing its members says nothing of them.
func TestWriteMemberListFollowsNewestList(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	benign := map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	// inside is outer holding the package, which holds members (nil: the
	// package's list is not stated).
	inside := func(outer string, h int, members []string) *result {
		r := &result{header: `{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":%d}`}
		pkg := map[string]any{"sha256": sum("package bytes"), "size": 4000, "type": "npm", "verdict": benign}
		r.files = []map[string]any{
			{
				"sha256": sum(outer), "size": 9000, "type": "tar", "verdict": benign,
				"contents": map[string]any{"children": []int{1}, "paths": []string{"vendor/pkg.tgz"}},
			},
			pkg,
		}
		if members != nil {
			children, paths := []int{}, []string{}
			for _, m := range members {
				children, paths = append(children, len(r.files)), append(paths, "package/"+m)
				r.files = append(r.files, map[string]any{"sha256": sum(m), "size": 10, "type": "javascript", "verdict": benign})
			}
			pkg["contents"] = map[string]any{"children": children, "paths": paths}
		}
		r.header = fmt.Sprintf(r.header, len(r.files))
		return at(r, h)
	}
	listed := func() []string {
		t.Helper()
		var paths []string
		if err := st.pool.QueryRow(ctx, `SELECT coalesce((SELECT c.paths FROM contents c JOIN samples s ON s.id = c.parent_id
			WHERE s.sha256 = $1), '{}')`, digestOf("package bytes")).Scan(&paths); err != nil {
			t.Fatal(err)
		}
		return paths
	}

	// The package is judged at 17:00 by a scan that lists nothing inside it,
	// as a legacy excerpt was; an archive scanned at 15:00 that lists its
	// members arrives later.
	pkg := at(archive(), 17)
	delete(pkg.files[0], "contents")
	pkg.files = pkg.files[:1]
	pkg.header = strings.Replace(pkg.header, `"files":2`, `"files":1`, 1)
	pkg.reports = pkg.reports[:1]
	pkg.write(ctx, t, st)
	inside("outer one", 15, []string{"a.js", "b.js"}).write(ctx, t, st)
	if got := listed(); !slices.Equal(got, []string{"package/a.js", "package/b.js"}) {
		t.Fatalf("listed %q: a newer opinion of the package kept out the only list stated for it", got)
	}
	// An older archive's list does not replace it, nor does one from the
	// same instant.
	inside("outer two", 14, []string{"a.js"}).write(ctx, t, st)
	inside("outer three", 15, []string{"c.js"}).write(ctx, t, st)
	if got := listed(); !slices.Equal(got, []string{"package/a.js", "package/b.js"}) {
		t.Errorf("listed %q: an older or same-instant list replaced the 15:00 one", got)
	}
	// A newer one does, and an emptied list stays empty against older ones.
	inside("outer four", 16, []string{}).write(ctx, t, st)
	inside("outer five", 13, []string{"a.js"}).write(ctx, t, st)
	if got := listed(); len(got) != 0 {
		t.Errorf("listed %q: an older list brought back members a newer scan emptied", got)
	}
}

// A rescan that finds the same thing under the same ruleset, within
// refreshAge, writes, and locks, no row but the artifact's scans row:
// verdicts, contents and refs keep the row version the first scan wrote, and
// a new engine alone changes none of them.
func TestWriteUnchangedTouchesNothing(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	r := archive()
	r.write(ctx, t, st)
	versions := func() string {
		t.Helper()
		var v string
		if err := st.pool.QueryRow(ctx, `SELECT string_agg(x, ',' ORDER BY x) FROM (
				SELECT 'v' || xmin::text AS x FROM verdicts UNION ALL
				SELECT 'c' || xmin::text FROM contents UNION ALL
				SELECT 'r' || xmin::text FROM refs) u`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := versions()
	r = at(r, 17)
	r.header = strings.Replace(r.header, `"engine":"3.0.0"`, `"engine":"3.0.1"`, 1)
	if got := r.write(ctx, t, st); got.Verdicts != 0 || got.Contents != 0 || got.Refs != 0 || got.Reports != 0 || got.Stamped != 1 {
		t.Errorf("stats %+v: want only the scan stamped", got)
	}
	if after := versions(); after != before {
		t.Errorf("row versions changed on an unchanged rescan:\n%s\n%s", before, after)
	}
}

// Results naming the same members, stored at once, neither deadlock nor
// fail: every writer takes shared rows in one order.
func TestWriteConcurrent(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	members := []string{"shared a", "shared b", "shared c", "shared d"}
	result := func(n int) *result {
		r := &result{header: strings.Replace(archive().header, `"files":2`, fmt.Sprintf(`"files":%d`, len(members)+1), 1)}
		children, paths := []int{}, []string{}
		for i := range members {
			children, paths = append(children, i+1), append(paths, fmt.Sprintf("m%d", i))
		}
		r.files = append(r.files, map[string]any{
			"sha256": sum(fmt.Sprintf("archive %d", n)), "size": 1000, "type": "npm",
			"verdict":  map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
			"contents": map[string]any{"children": children, "paths": paths},
		})
		for i, m := range members {
			class := []string{"benign", "suspicious", "hostile"}[(n+i)%3]
			r.files = append(r.files, map[string]any{
				"sha256": sum(m), "size": 100, "type": "javascript",
				"verdict": map[string]any{"outcome": "ok", "class": class},
			})
		}
		return r
	}
	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for n := range writers {
		body := result(n).body(t).Bytes()
		wg.Go(func() {
			files, err := scanresult.Decode(body)
			if err == nil {
				_, err = st.Write(ctx, files)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// A member that got worse queues the archives on disk that hold it, through
// a container nested between them.
func TestWriteRepairsThroughNesting(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	nested := &result{header: strings.Replace(archive().header, `"files":2`, `"files":3`, 1), files: []map[string]any{
		{
			"sha256": sum("outer"), "size": 9000, "type": "zip",
			"verdict":  map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"inner.tar"}},
		},
		{
			"sha256": sum("inner"), "size": 5000, "type": "tar",
			"verdict":  map[string]any{"outcome": "ok", "class": "benign"},
			"contents": map[string]any{"children": []int{2}, "paths": []string{"x.js"}},
		},
		{"sha256": sum("deep"), "size": 100, "type": "javascript", "verdict": map[string]any{"outcome": "ok", "class": "benign"}},
	}}
	nested.write(ctx, t, st)
	place(ctx, t, st, digestOf("outer"), "pool/outer.zip")

	// The deep file's own scan, under a newer ruleset, finds it hostile.
	worse := &result{
		header: strings.NewReplacer(`"files":2`, `"files":1`, `"ruleset":"r1"`, `"ruleset":"r2"`, "T15:", "T16:").Replace(archive().header),
		files: []map[string]any{{
			"sha256": sum("deep"), "size": 100, "type": "javascript",
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 3},
		}},
	}
	if got := worse.write(ctx, t, st); got.Requeued != 1 {
		t.Errorf("requeued %d, want the outer archive", got.Requeued)
	}
	if p, ok := priorities(ctx, t, st)[hexOf(digestOf("outer"))]; !ok || p != QueueRepair {
		t.Errorf("outer archive queued %v at %v, want QueueRepair", ok, p)
	}
}

// A file whose size nobody has said is never handed to a worker with a size
// limit; the scan that reads it says, and fills it in.
func TestUnknownSize(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	ingest(ctx, t, st, QueueNew, Arrival{SHA256: digestOf("package bytes"), Path: "pool/pkg.tgz"})
	if jobs, err := st.Candidates(ctx, QueueNew, 10, 1<<20); err != nil || len(jobs) != 0 {
		t.Errorf("candidates %+v, %v: a file of unknown size went to a limited worker", jobs, err)
	}
	if jobs, err := st.Candidates(ctx, QueueNew, 10, 0); err != nil || len(jobs) != 1 {
		t.Errorf("candidates %+v, %v: an unlimited worker should take it", jobs, err)
	}
	if got := archive().write(ctx, t, st); got.Retyped != 1 {
		t.Errorf("retyped %d, want the scan to fill type and size", got.Retyped)
	}
	var size *int64
	if err := st.pool.QueryRow(ctx, `SELECT size_bytes FROM samples WHERE sha256 = $1`, digestOf("package bytes")).Scan(&size); err != nil ||
		size == nil || *size != 4000 {
		t.Errorf("size %v, %v; want the scan's 4000", size, err)
	}
}

// One rule decides which releases a claim names.
func TestExactVersions(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	for affected, want := range map[string]string{
		"":              "",
		"*":             "",
		">= 1.0":        "",
		"> 0":           "",
		"^2.1.0":        "",
		"1.0.0":         "1.0.0",
		"1.0.1, 1.0.2":  "1.0.1,1.0.2",
		"= 1.0.0":       "1.0.0",
		"==1.0.0":       "1.0.0",
		"=1.0.0,=1.0.1": "1.0.0,1.0.1",
		"1.0~rc1":       "",
	} {
		var got *string
		if err := st.pool.QueryRow(ctx, `SELECT array_to_string(exact_versions($1), ',')`, affected).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if (got == nil) != (want == "") || (got != nil && *got != want) {
			t.Errorf("exact_versions(%q) = %v, want %q (empty: every release)", affected, got, want)
		}
	}
}

// A file that loses its last path leaves the queue: nothing could be handed
// to a worker.
func TestUnlocateUnqueues(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: digestOf("twice"), Size: 100, Path: "pool/a"},
		Arrival{SHA256: digestOf("twice"), Size: 100, Path: "pool/b"})
	if err := st.Unlocate(ctx, hexOf(digestOf("twice")), "pool/a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := priorities(ctx, t, st)[hexOf(digestOf("twice"))]; !ok {
		t.Fatal("a file with a path left was unqueued")
	}
	if err := st.Unlocate(ctx, hexOf(digestOf("twice")), "pool/b"); err != nil {
		t.Fatal(err)
	}
	if _, ok := priorities(ctx, t, st)[hexOf(digestOf("twice"))]; ok {
		t.Error("a file with no path left is still queued")
	}
}

// What no row can hold is refused, not an error that fails the batch on
// every retry.
func TestIngestRefusesUnstorable(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	got := ingest(ctx, t, st, QueueNew,
		Arrival{SHA256: digestOf("long path"), Size: 100, Path: "pool/" + strings.Repeat("x", 1100)},
		Arrival{SHA256: digestOf("long name"), Size: 100, Path: "pool/n", Name: "pkg:npm/" + strings.Repeat("x", 2100)},
		Arrival{SHA256: digestOf("fine"), Size: 100, Path: "pool/fine"})
	if got.Refused != 2 || got.New != 1 {
		t.Errorf("%+v: want two refused and the third stored", got)
	}
}

// A record raised to hostile never says it never fires.
func TestRaiseByNeverFires(t *testing.T) {
	never, three := -1, 3
	r := &Record{Class: "benign", FiresAt: &never}
	r.RaiseBy(&Raised{By: []Raiser{{FiresAt: nil}}})
	if r.Class != "hostile" || r.FiresAt != nil {
		t.Errorf("class %q, fires at %v; want hostile with no level", r.Class, r.FiresAt)
	}
	r.RaiseBy(&Raised{By: []Raiser{{FiresAt: &three}}})
	if r.FiresAt == nil || *r.FiresAt != 3 {
		t.Errorf("fires at %v, want 3 from what raised it", r.FiresAt)
	}
}

// A member's jurors are part of its opinion: an older archive's scan that
// names a juror a newer one dropped does not bring it back, and storing both
// again writes nothing.
func TestWriteMemberJurorsFollowNewestScan(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	newer := at(archive(), 16) // the script's line without a floor juror
	delete(newer.files[1], "floor")
	newer.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "ml"}
	older := at(archive(), 15) // another archive, an hour older, naming the floor
	older.files[0]["sha256"] = sum("another package")

	floor := func() bool {
		t.Helper()
		var has bool
		if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM verdicts v JOIN samples s ON s.id = v.sample_id
			WHERE s.sha256 = $1 AND v.scanner_id = $2)`, digestOf("script bytes"), jurors["floor"]).Scan(&has); err != nil {
			t.Fatal(err)
		}
		return has
	}
	older.write(ctx, t, st)
	if !floor() {
		t.Fatal("the older archive's floor juror was not stored")
	}
	newer.write(ctx, t, st)
	if floor() {
		t.Fatal("the newer scan's dropped juror stands")
	}
	if got := older.write(ctx, t, st); floor() || got.Verdicts != 0 {
		t.Errorf("stats %+v, floor %v: an older scan brought back a juror a newer one dropped", got, floor())
	}
	if got := newer.write(ctx, t, st); got.Verdicts != 0 || got.JurorsRemoved != 0 {
		t.Errorf("stats %+v: storing the newer result again wrote something", got)
	}
}

// A member's line from an archive scan replaces a file's stored verdict only
// when it says as much, or is tighter. Found by the migration rehearsal on
// real data (2026-11-13): a stealer scanned on its own was judged hostile at
// L12, with the interpretation "Salat Stealer malware" and three crit-5
// findings; minutes later an archive holding it was scanned, and that
// archive's line for it (L25, no reason, no findings) replaced the richer
// verdict, so lookups answered a weaker, unexplained hostile.
func TestWriteMemberLineKeepsRicherVerdict(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	header := func(h, files int) string {
		return fmt.Sprintf(`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T%02d:00:00Z","ms":40},"files":%d}`, h, files)
	}
	top := []map[string]any{
		{"id": "objectives/collection/multi-source::go-keylogger-screen-browser-stealer-suite", "crit": 5},
		{"id": "objectives/command-and-control/remote-command/tasking::go-task-dispatcher-with-socks-relay", "crit": 5},
		{"id": "objectives/credential-access/browser/chromium::go-browser-login-query-with-keylogging", "crit": 5},
	}
	stealer := sum("stealer bytes")
	// The stealer scanned on its own: hostile at L12, explained.
	own := &result{header: header(15, 1), files: []map[string]any{{
		"sha256": stealer, "size": 900, "type": "macho",
		"verdict": map[string]any{
			"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "ml",
			"reason": "Salat Stealer malware", "top": top,
		},
	}}}
	own.write(ctx, t, st)
	// line is an archive, scanned at hour h, holding the stealer, whose line
	// for it carries verdict.
	line := func(archive string, h int, verdict map[string]any) Stats {
		t.Helper()
		r := &result{header: header(h, 2), files: []map[string]any{
			{
				"sha256": sum(archive), "size": 9000, "type": "zip",
				"verdict":  map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
				"contents": map[string]any{"children": []int{1}, "paths": []string{"bin/stealer"}},
			},
			{"sha256": stealer, "size": 900, "type": "macho", "verdict": verdict},
		}}
		return r.write(ctx, t, st)
	}
	stored := func() *Record {
		t.Helper()
		rec, err := st.BySHA256(ctx, digestOf("stealer bytes"))
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	level := func(r *Record) int {
		if r.FiresAt == nil {
			return -2
		}
		return *r.FiresAt
	}

	// Thinner and looser: held back; the stealer keeps its own verdict.
	if got := line("an archive", 16, map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 25}); got.Deferred != 1 {
		t.Errorf("stats %+v: want the archive's thin line for the stealer deferred", got)
	}
	if r := stored(); level(r) != 12 || r.Reason != "Salat Stealer malware" || len(r.Findings) != 3 {
		t.Fatalf("stored L%d %q %v: a thinner, looser line replaced the stealer's own verdict", level(r), r.Reason, r.Findings)
	}
	// Thinner, and benign: held back as well.
	line("a cleaner archive", 17, map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1})
	if r := stored(); r.Class != "hostile" || level(r) != 12 {
		t.Errorf("stored %s L%d: a thin benign line demoted the stealer", r.Class, level(r))
	}
	// As rich, though looser: a newer opinion that says as much stands.
	line("a third archive", 18, map[string]any{
		"outcome": "ok", "class": "hostile", "fires_at": 25,
		"reason": "Salat Stealer variant", "top": top,
	})
	if r := stored(); level(r) != 25 || r.Reason != "Salat Stealer variant" {
		t.Errorf("stored L%d %q: an equally rich line was held back", level(r), r.Reason)
	}
	// Thin, but tighter: newer rules convicting harder still land.
	line("a fourth archive", 19, map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 5})
	if r := stored(); level(r) != 5 {
		t.Errorf("stored L%d: a tighter line was held back for being thin", level(r))
	}
}

// The same rule holds whichever arrives first. In the rehearsal the
// stealer's case came from parallel conversion: the archive's line (scanned
// at 21:01) was written before the stealer's own result (scanned at 20:57),
// which was then refused as older. A file's own scan that is richer than a
// newer opinion an archive's line gave it, and no looser, takes its place;
// seeing the line again changes nothing.
func TestWriteOwnScanReclaimsFromThinnerLine(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	header := func(h, files int) string {
		return fmt.Sprintf(`{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T%02d:00:00Z","ms":40},"files":%d}`, h, files)
	}
	stealer := sum("stealer bytes")
	archive := &result{header: header(16, 2), files: []map[string]any{
		{
			"sha256": sum("an archive"), "size": 9000, "type": "zip",
			"verdict":  map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"bin/stealer"}},
		},
		{
			"sha256": stealer, "size": 900, "type": "macho",
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 25},
			"ml":      map[string]any{"class": "hostile", "fires_at": 25, "prob": 0.99},
		},
	}}
	archive.write(ctx, t, st)
	own := &result{header: header(15, 1), files: []map[string]any{{
		"sha256": stealer, "size": 900, "type": "macho",
		"verdict": map[string]any{
			"outcome": "ok", "class": "hostile", "fires_at": 12, "by": "ml",
			"reason": "Salat Stealer malware",
			"top":    []map[string]any{{"id": "objectives/collection/multi-source::go-keylogger-screen-browser-stealer-suite", "crit": 5}},
		},
		"floor": map[string]any{"class": "hostile", "hostile": 6, "suspicious": 1},
	}}}
	own.write(ctx, t, st)
	rec, err := st.BySHA256(ctx, digestOf("stealer bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.FiresAt == nil || *rec.FiresAt != 12 || rec.Reason != "Salat Stealer malware" || len(rec.Findings) != 1 {
		t.Fatalf("record %+v: the stealer's own, richer scan did not take the place of the archive's thinner line", rec)
	}
	// The line's ml juror, which the own scan does not carry, went with it.
	var ml bool
	if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM verdicts v JOIN samples s ON s.id = v.sample_id
		WHERE s.sha256 = $1 AND v.scanner_id = $2)`, digestOf("stealer bytes"), jurors["ml"]).Scan(&ml); err != nil || ml {
		t.Errorf("ml juror kept %v, %v: the thinner line's juror outlived the opinion it belonged to", ml, err)
	}
	if got := archive.write(ctx, t, st); got.Verdicts != 0 || got.JurorsRemoved != 0 {
		t.Errorf("stats %+v: seeing the archive again rewrote the stealer", got)
	}
}

// A member's floor or ml juror that finds nothing (benign, firing at no
// level) is not stored: nearly every member says it, and atomscan's own
// benign row says as much. A file scanned on its own keeps it, since the
// triage queues read the model's score of the files they hand out, and an
// archive's line must not take that away.
func TestWriteQuietMemberJurors(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	quiet := func(prob float64) map[string]any {
		return map[string]any{"class": "benign", "fires_at": -1, "prob": prob}
	}
	held := func(want ...string) {
		t.Helper()
		var got []string
		if err := st.pool.QueryRow(ctx, `SELECT array_agg(sc.name ORDER BY sc.id) FROM verdicts v
			JOIN scanners sc ON sc.id = v.scanner_id JOIN samples s ON s.id = v.sample_id
			WHERE s.sha256 = $1`, digestOf("script bytes")).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("the member's rows %v, want %v", got, want)
		}
	}
	r := at(archive(), 15) // the member's ml reading is quiet
	r.write(ctx, t, st)
	held("atomscan", "floor")

	// The model fires: stored. Quiet again: removed, as a juror the line no
	// longer names is.
	r = at(archive(), 16)
	r.files[1]["ml"] = map[string]any{"class": "suspicious", "fires_at": 900, "prob": 0.61}
	r.write(ctx, t, st)
	held("atomscan", "floor", "ml")
	at(archive(), 17).write(ctx, t, st)
	held("atomscan", "floor")

	// Scanned on its own, the file keeps the model's quiet reading, and an
	// archive's newer line, which carries one too, replaces it.
	r = archive()
	alone := at(&result{
		header: strings.Replace(r.header, `"files":2`, `"files":1`, 1),
		files: []map[string]any{{
			"sha256": r.files[1]["sha256"], "size": 300, "type": "javascript", "report": r.files[1]["report"],
			"verdict": r.files[1]["verdict"], "floor": r.files[1]["floor"], "ml": quiet(0.04),
		}},
		reports: r.reports[1:],
	}, 18)
	alone.write(ctx, t, st)
	held("atomscan", "floor", "ml")
	r = at(archive(), 19)
	r.files[1]["ml"] = quiet(0.03)
	r.write(ctx, t, st)
	held("atomscan", "floor", "ml")
	var prob float64
	if err := st.pool.QueryRow(ctx, `SELECT (v.summary->>'prob')::float8 FROM verdicts v JOIN samples s ON s.id = v.sample_id
		WHERE s.sha256 = $1 AND v.scanner_id = $2`, digestOf("script bytes"), jurors["ml"]).Scan(&prob); err != nil || prob != 0.03 {
		t.Errorf("ml prob %v, %v; want the newer line's 0.03", prob, err)
	}
	// Every rewrite of the member's row kept its report, which never changed.
	if report, err := st.Report(ctx, digestOf("script bytes")); err != nil || string(report) != r.reports[1] {
		t.Errorf("report %q, %v; want it kept", report, err)
	}
}

// A newer scan that agrees with a stored reading confirms it, writing its
// own time, when it ran under another ruleset or more than refreshAge later:
// the rule scan applies before trusting hopper's verdict on a dependency.
// Without it the newer scan left no trace, and an older scan's different
// reading, arriving after it, replaced the newer one. Seen in the migration
// rehearsal: a member read alike on Sep 29 and Nov 7 kept Oct 18's reading,
// from another engine, because Oct 18's result was stored last.
func TestWriteAgreeingNewerScanRefreshes(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	// from is the fixture's result as the archive holder scanned it at hour
	// h of day under ruleset: each holder holds the same script.
	from := func(holder, day string, h int, ruleset string) *result {
		r := at(archive(), h)
		r.files[0]["sha256"] = sum(holder)
		r.header = strings.NewReplacer(`"ruleset":"r1"`, `"ruleset":"`+ruleset+`"`, "2026-11-12", day).Replace(r.header)
		return r
	}
	member := func(want string, at time.Time) {
		t.Helper()
		var ruleset string
		var formed time.Time
		if err := st.pool.QueryRow(ctx, `SELECT v.ruleset, v.formed_at FROM verdicts v JOIN samples s ON s.id = v.sample_id
			WHERE s.sha256 = $1 AND v.scanner_id = $2`, digestOf("script bytes"), atomscan).Scan(&ruleset, &formed); err != nil {
			t.Fatal(err)
		}
		if ruleset != want || !formed.Equal(at) {
			t.Errorf("the member's reading %s formed %s, want %s formed %s", ruleset, formed.UTC(), want, at)
		}
	}
	day := func(d string, h int) time.Time {
		at, err := time.Parse(time.DateOnly, d)
		if err != nil {
			t.Fatal(err)
		}
		return at.Add(time.Duration(h) * time.Hour)
	}

	from("archive a", "2026-11-12", 15, "r1").write(ctx, t, st)
	from("archive c", "2026-11-12", 17, "r2").write(ctx, t, st) // agrees, newer, another ruleset
	member("r2", day("2026-11-12", 17))
	older := from("archive b", "2026-11-12", 16, "r3") // disagrees, and arrives last
	older.files[1]["verdict"] = map[string]any{"outcome": "ok", "class": "benign", "fires_at": -1}
	delete(older.files[1], "floor")
	older.write(ctx, t, st)
	if class := atomscanClass(ctx, t, st, "script bytes"); class != "hostile" {
		t.Errorf("class %q: an older reading, arriving late, replaced a newer one that confirmed hostile", class)
	}
	member("r2", day("2026-11-12", 17))

	// Under one ruleset, agreeing refreshes the row only once it is more
	// than refreshAge old.
	from("archive c", "2026-12-10", 17, "r2").write(ctx, t, st)
	member("r2", day("2026-11-12", 17))
	from("archive c", "2026-12-14", 17, "r2").write(ctx, t, st)
	member("r2", day("2026-12-14", 17))
}
