package hopper

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The SQL literal list and the Go predicate must classify every rel identically;
// they are two spellings of one rule, and a drift between them would silently
// change what queries mean without failing a build.
func TestContainmentRelsSQLMatchesPredicate(t *testing.T) {
	all := []Rel{RelContained, RelUnpacked, RelFetched, RelRegistry}
	inSQL := func(r Rel) bool {
		return slices.Contains(strings.Split(strings.Trim(containmentRelsSQL, "()"), ", "), "'"+string(r)+"'")
	}
	for _, r := range all {
		if r.IsContainment() != inSQL(r) {
			t.Errorf("rel %q: IsContainment()=%v but SQL membership=%v",
				r, r.IsContainment(), inSQL(r))
		}
	}
}

// KnownSHA256 answers "can you produce these bytes", not "do you have a row".
// The distinction is the whole point: a producer that hears "known" never sends
// the bytes, so a wrong yes loses them permanently while a wrong no costs one
// redundant upload.
func TestKnownSHA256ReportsOnlyRetrievableBytes(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const (
		topLevel  = "a1" + "00000000000000000000000000000000000000000000000000000000000000"
		archive   = "b2" + "00000000000000000000000000000000000000000000000000000000000000"
		member    = "c3" + "00000000000000000000000000000000000000000000000000000000000000"
		dep       = "d4" + "00000000000000000000000000000000000000000000000000000000000000"
		gone      = "e5" + "00000000000000000000000000000000000000000000000000000000000000"
		neverSeen = "f6" + "00000000000000000000000000000000000000000000000000000000000000"
	)

	// A standalone artifact with its own bytes on disk.
	mustInsert(t, ctx, db, &Sample{SHA256: topLevel, Path: "unknown/uploads/a1/00/pkg.tgz"})
	// The archive, and a member genuinely inside it: recoverable by extraction.
	mustInsert(t, ctx, db, &Sample{SHA256: archive, Path: "unknown/foraged/npm/app.tgz"})
	mustInsert(t, ctx, db, &Sample{
		SHA256: member, Path: "unknown/foraged/npm/app.tgz!!lib/index.js",
		Parent: archive, LocationRel: string(RelContained),
	})
	// A dependency the archive merely *named*. Its bytes were never inside the
	// archive, so there is nothing to extract them from — the case that made
	// hopper claim artifacts it had never held.
	mustInsert(t, ctx, db, &Sample{
		SHA256: dep, Path: "unknown/foraged/npm/app.tgz!!evil-1.0.0.tgz",
		Parent: archive, LocationRel: string(RelFetched),
	})
	// Bytes hopper knows are gone from disk.
	mustInsert(t, ctx, db, &Sample{SHA256: gone, Path: "unknown/foraged/npm/vanished.tgz"})
	if err := db.SetSkip(ctx, gone, "missing"); err != nil {
		t.Fatalf("SetSkip: %v", err)
	}

	known, err := db.KnownSHA256(ctx, []string{topLevel, archive, member, dep, gone, neverSeen})
	if err != nil {
		t.Fatalf("KnownSHA256: %v", err)
	}
	has := func(sha string) bool { return slices.Contains(known, sha) }

	for _, tc := range []struct {
		sha, name string
		want      bool
		why       string
	}{
		{topLevel, "top-level", true, "its own bytes are on disk"},
		{archive, "archive", true, "its own bytes are on disk"},
		{member, "contained member", true, "extractable from the archive that contains it"},
		{dep, "fetched dependency", false, "never inside the archive that named it"},
		{gone, "missing", false, "hopper already recorded the bytes as gone"},
		{neverSeen, "absent", false, "no row at all"},
	} {
		if has(tc.sha) != tc.want {
			t.Errorf("%s: known=%v, want %v — %s", tc.name, has(tc.sha), tc.want, tc.why)
		}
	}
}
