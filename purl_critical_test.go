package hopper

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestVersionedPURLSelectsLowestFiringLevel(t *testing.T) {
	for _, backend := range testBackends {
		t.Run(backend.name, func(t *testing.T) {
			db := backend.open(t)
			checkVersionedPURLSelectsLowestFiringLevel(t, db)
		})
	}
}

func checkVersionedPURLSelectsLowestFiringLevel(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	const base = "pkg:pypi/payload-choice"
	shaFor := func(name string) string {
		ids := map[string]int{
			"critical-a": 1, "critical-b": 2, "suspicious": 3, "clean": 4,
			"unknown": 5, "registry": 6, "pending": 7, "other-version": 8,
			"fallback-clean": 9, "fallback-unknown": 10,
		}
		return fmt.Sprintf("%064x", ids[name])
	}
	insert := func(sha, version, result, at, filetype string) {
		t.Helper()
		sha = shaFor(sha)
		mustInsert(t, ctx, db, &Sample{SHA256: sha, Source: "test", PURLBase: base, Version: version})
		cleave := fmt.Appendf(nil, `{"fs":[{"sha":%q,"type":%q,"dp":0}]}`, sha, filetype)
		if err := db.UpdateCleaveResult(ctx, sha, cleave, nil, ""); err != nil {
			t.Fatal(err)
		}
		if result != "" {
			if err := db.UpdateLitmusResult(ctx, sha, []byte(result)); err != nil {
				t.Fatal(err)
			}
		}
		query := `UPDATE samples SET analyzed_at = $1 WHERE sha256 = $2`
		if db.pool != nil {
			when, err := time.Parse(time.RFC3339, at)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.pool.Exec(ctx, query, when, sha); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := db.lite.ExecContext(ctx, `UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`, at, sha); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert("critical-a", "1.0", `{"ml":{"lvl":0,"eng":"test"}}`, "2026-01-01T00:00:00Z", "zip")
	insert("critical-b", "1.0", `{"lvl":0}`, "2026-01-01T00:00:00Z", "gzip")
	insert("suspicious", "1.0", `{"l":100}`, "2026-01-02T00:00:00Z", "zip")
	insert("clean", "1.0", `{"lvl":-1}`, "2026-01-03T00:00:00Z", "gzip")
	insert("unknown", "1.0", `{"lvl":null}`, "2026-01-04T00:00:00Z", "zip")
	insert("registry", "1.0", `{"lvl":0}`, "2026-01-05T00:00:00Z", "registry")
	insert("pending", "1.0", "", "2026-01-06T00:00:00Z", "zip")
	insert("other-version", "2.0", `{"lvl":1}`, "2026-01-07T00:00:00Z", "zip")
	insert("fallback-clean", "3.0", `{"lvl":-1}`, "2026-01-01T00:00:00Z", "zip")
	insert("fallback-unknown", "3.0", `{"lvl":null}`, "2026-01-08T00:00:00Z", "zip")

	check := func(version, want string) {
		t.Helper()
		want = shaFor(want)
		got, err := db.SampleByPURL(ctx, base, version)
		if err != nil {
			t.Fatal(err)
		}
		if got.SHA256 != want {
			t.Fatalf("sample version %q = %s, want %s", version, got.SHA256, want)
		}
		rec, err := db.LookupRecord(ctx, "", base, version)
		if err != nil {
			t.Fatal(err)
		}
		if rec.SHA256 == nil || *rec.SHA256 != want {
			t.Fatalf("record version %q = %+v, want %s", version, rec, want)
		}
	}
	check("1.0", "critical-a") // Zero counts; equal levels and timestamps use the digest.
	check("2.0", "other-version")
	check("3.0", "fallback-clean") // Missing levels cannot displace a measured result.
	check("", "fallback-unknown")  // Versionless behavior stays newest analyzed.

	// Warm both caches, then make a previously losing sibling win. The
	// changed digest is absent from the SHA cache and does not back the
	// cached PURL record, so invalidation must use its package identity.
	if err := db.UpdateLitmusResult(ctx, shaFor("suspicious"), []byte(`{"lvl":0}`)); err != nil {
		t.Fatal(err)
	}
	check("1.0", "suspicious")
	if err := db.UpdateLitmusResult(ctx, shaFor("suspicious"), []byte(`{"lvl":-1}`)); err != nil {
		t.Fatal(err)
	}
	check("1.0", "critical-a")
	exact, err := db.LookupRecord(ctx, shaFor("clean"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if exact.FiresAt == nil || *exact.FiresAt != -1 {
		t.Fatalf("digest lookup changed: %+v", exact)
	}
}
