package hopper

import (
	"testing"
	"time"
)

func TestIncomingCursorPreservesPathsWithSameTimestampAndSHA(t *testing.T) {
	db := openTestDB(t)
	ctx := t.Context()
	seen := time.Now().UTC().Add(-2 * time.Hour)
	mustInsert(t, ctx, db, &Sample{SHA256: "shared", Path: "incoming/a", Label: "unknown"})
	if err := db.UpsertLocation(ctx, &SampleLocation{SHA256: "shared", Path: "incoming/b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.lite.ExecContext(ctx, "UPDATE sample_locations SET first_seen_at = ? WHERE sha256 = ?", seen.Format(time.RFC3339Nano), "shared"); err != nil {
		t.Fatal(err)
	}
	query := IncomingQuery{Before: time.Now().UTC(), Limit: 1, Class: IncomingUnknown}
	for _, want := range []string{"incoming/a", "incoming/b"} {
		rows, err := db.OldestIncomingLocations(ctx, query)
		if err != nil || len(rows) != 1 || rows[0].Path != want {
			t.Fatalf("page = %+v, %v; want %s", rows, err, want)
		}
		query.After = IncomingCursor{FirstSeenAt: rows[0].FirstSeenAt, SHA256: rows[0].SHA256, Path: rows[0].Path}
	}
	rows, err := db.OldestIncomingLocations(ctx, query)
	if err != nil || len(rows) != 0 {
		t.Fatalf("final page = %+v, %v; want exhausted feed", rows, err)
	}
}
