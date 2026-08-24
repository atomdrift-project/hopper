package hopper

import (
	"os"
	"testing"
)

// The migration lock is the one thing standing between two hoppers and the
// index race of 2026-08-24, and it cannot be exercised on SQLite: advisory
// locks are a PostgreSQL primitive. Set HOPPER_TEST_DSN to run it.
//
// It takes and releases only its own advisory key, so it is safe against a
// live cluster — advisory locks conflict with nothing but the same key.
func TestMigrationLockIsExclusive(t *testing.T) {
	dsn := os.Getenv("HOPPER_TEST_DSN")
	if dsn == "" {
		t.Skip("HOPPER_TEST_DSN not set")
	}

	open := func() *DB {
		t.Helper()
		db, err := Open(t.Context(), dsn, AppName("hopper"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(db.Close)
		return db
	}
	first, second := open(), open()

	release, acquired, err := first.tryMigrationLock(t.Context())
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if !acquired {
		t.Fatal("first migrator did not get an uncontended lock")
	}

	// The whole point: a second process must be turned away rather than queued
	// behind it. Waiting is what let a DROP sit 22 minutes on an index another
	// hopper was building.
	if _, got, err := second.tryMigrationLock(t.Context()); err != nil {
		t.Fatalf("second lock: %v", err)
	} else if got {
		t.Fatal("two processes hold the migration lock at once")
	}

	release()

	// And releasing must actually hand it over, not merely stop using it.
	releaseSecond, got, err := second.tryMigrationLock(t.Context())
	if err != nil {
		t.Fatalf("second lock after release: %v", err)
	}
	if !got {
		t.Fatal("lock was not released to the next migrator")
	}
	releaseSecond()
}
