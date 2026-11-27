package store

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"
)

// claim records what a source says of a subject through the ledger's writer,
// which cites what the claim names.
func claim(ctx context.Context, t *testing.T, st *Store, source, subject, affected, what string) {
	t.Helper()
	if _, err := st.AddSightings(ctx, []Sighting{{
		Source: source, Operator: source, Subject: subject, Affected: affected, Claim: what,
	}}); err != nil {
		t.Fatal(err)
	}
}

// A first scan of a package some source has called malicious, in another
// release, is queued as compromised; a suspicious claim is not enough.
func TestCompromisedAtIngest(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	claim(ctx, t, st, "osv", "pkg:npm/chalk", "5.6.1", "malicious")
	// Any claim naming a release makes it sighted, so this one names none
	// on disk: the test is what it says of the package's other releases.
	claim(ctx, t, st, "socket", "pkg:npm/popular", "0.0.1", "suspicious")

	arrive := func(p Priority, bytes, name, version string, size int64) {
		t.Helper()
		ingest(ctx, t, st, p, Arrival{SHA256: digestOf(bytes), Size: size, Path: "pool/" + bytes, Name: name, Version: version})
	}
	arrive(QueueNew, "chalk 5.6.1", "pkg:npm/chalk", "5.6.1", 100)
	arrive(QueueNew, "chalk 5.6.0", "pkg:npm/chalk", "5.6.0", 100)
	arrive(QueueNew, "chalk 5.6.2", "pkg:npm/chalk", "5.6.2", bigFile+1)
	arrive(QueueUpload, "chalk 5.5.0", "pkg:npm/chalk", "5.5.0", 100)
	arrive(QueueNew, "popular 1.0.0", "pkg:npm/popular", "1.0.0", 100)
	arrive(QueueNew, "loose", "", "", 100)
	want := map[string]Priority{
		hexOf(digestOf("chalk 5.6.1")):   QueueSighted, // the release the claim names
		hexOf(digestOf("chalk 5.6.0")):   QueueCompromised,
		hexOf(digestOf("chalk 5.6.2")):   QueueCompromised, // however big
		hexOf(digestOf("chalk 5.5.0")):   QueueUpload,      // someone is waiting on it
		hexOf(digestOf("popular 1.0.0")): QueueNew,
		hexOf(digestOf("loose")):         QueueNew,
	}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Fatalf("priorities %v, want %v", got, want)
	}

	// A repair queues them as ingest would.
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.QueueUnscanned(ctx); err != nil {
		t.Fatal(err)
	}
	want[hexOf(digestOf("chalk 5.5.0"))] = QueueCompromised // nobody is waiting on it now
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("after QueueUnscanned: priorities %v, want %v", got, want)
	}
}

// A new malicious claim about a package raises the first scans of its
// releases already queued, and nothing else.
func TestCompromisedOnSighting(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	release(ctx, t, st, "chalk 1.0.0", "pkg:npm/chalk", "1.0.0", "")
	ingest(ctx, t, st, QueueNew, Arrival{
		SHA256: digestOf("chalk 2.0.0"), Size: bigFile + 1,
		Path: "pool/chalk 2.0.0", Name: "pkg:npm/chalk", Version: "2.0.0",
	})
	release(ctx, t, st, "chalk 3.0.0", "pkg:npm/chalk", "3.0.0", "")
	judge(ctx, t, st, "chalk 3.0.0", "benign", -1, nil, nil)
	if ok, err := st.Rescan(ctx, digestOf("chalk 3.0.0"), time.Now()); err != nil || !ok {
		t.Fatalf("rescan: %v, %v", ok, err)
	}
	release(ctx, t, st, "lodash 1.0.0", "pkg:npm/lodash", "1.0.0", "")
	want := map[string]Priority{
		hexOf(digestOf("chalk 1.0.0")):  QueueNew,
		hexOf(digestOf("chalk 2.0.0")):  QueueBigArchive,
		hexOf(digestOf("chalk 3.0.0")):  QueueRequested,
		hexOf(digestOf("lodash 1.0.0")): QueueNew,
	}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Fatalf("priorities %v, want %v", got, want)
	}

	claim(ctx, t, st, "socket", "pkg:npm/lodash", "0.0.1", "suspicious")
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("a suspicious claim moved %v, want %v", got, want)
	}

	claim(ctx, t, st, "osv", "pkg:npm/chalk", "9.9.9", "malicious")
	want[hexOf(digestOf("chalk 1.0.0"))] = QueueCompromised
	want[hexOf(digestOf("chalk 2.0.0"))] = QueueCompromised
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("after a malicious claim: priorities %v, want %v (a rescan stays a rescan)", got, want)
	}

	// A claim turning suspicious to malicious is a new malicious claim.
	claim(ctx, t, st, "socket", "pkg:npm/lodash", "0.0.1", "malicious")
	want[hexOf(digestOf("lodash 1.0.0"))] = QueueCompromised
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("after lodash turned malicious: priorities %v, want %v", got, want)
	}
}

// A sighting queues a cited file on disk that waits for its first scan
// though nothing queued it, and leaves alone one with no path or a verdict.
func TestCiteQueuesUnqueued(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	for _, name := range []string{"waiting", "nowhere", "scanned"} {
		release(ctx, t, st, name, "", "", "")
	}
	judge(ctx, t, st, "scanned", "benign", -1, nil, nil)
	if _, err := st.pool.Exec(ctx, `DELETE FROM queue`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM locations WHERE path = 'pool/nowhere'`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"waiting", "nowhere", "scanned"} {
		sight(ctx, t, st, "feed", hexOf(digestOf(name)), "")
	}
	want := map[string]Priority{hexOf(digestOf("waiting")): QueueSighted}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("priorities %v, want %v", got, want)
	}
}

// The newest end of a priority is the files hopper saw last, never-tried
// first: a file queued again is no newer, and a leased one is passed over.
func TestNewestCandidates(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	names := []string{"f0", "f1", "f2", "f3", "f4"}
	for _, name := range names {
		release(ctx, t, st, name, "", "", "")
	}
	// f0 queued again just now: newest by queue time, oldest by arrival.
	if _, err := st.pool.Exec(ctx, `UPDATE queue SET queued_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE queue SET queued_at = now()
		WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`, digestOf("f0")); err != nil {
		t.Fatal(err)
	}
	order := func(jobs []Job, err error) []string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, j := range jobs {
			for _, name := range names {
				if j.SHA256 == hexOf(digestOf(name)) {
					out = append(out, name)
				}
			}
		}
		return out
	}
	if got := order(st.NewestCandidates(ctx, QueueNew, 3, 0, nil)); !slices.Equal(got, []string{"f4", "f3", "f2"}) {
		t.Errorf("newest %v, want f4 f3 f2", got)
	}
	if _, err := st.Lease(ctx, []string{hexOf(digestOf("f4"))}, []time.Duration{time.Hour}); err != nil {
		t.Fatal(err)
	}
	// f3's lease has run out: it comes after every file never tried.
	if _, err := st.Lease(ctx, []string{hexOf(digestOf("f3"))}, []time.Duration{-time.Minute}); err != nil {
		t.Fatal(err)
	}
	if got := order(st.NewestCandidates(ctx, QueueNew, 10, 0, nil)); !slices.Equal(got, []string{"f2", "f1", "f0", "f3"}) {
		t.Errorf("newest after leases %v, want f2 f1 f0 f3", got)
	}
}
