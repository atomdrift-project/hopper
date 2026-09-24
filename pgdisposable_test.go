package hopper

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// openDisposablePG opens a migrated hopper database on Postgres for the tests
// whose SQL is Postgres-only or diverges from its SQLite twin — the backfill
// sweeps, UPDATE … FROM with unnest, window-function ordering.
//
// Set HOPPER_TEST_PG_DSN to a database you are willing to have written to: a
// throwaway local cluster, never a shared one. Each test gets its own schema
// (created here, dropped on cleanup) so tests neither see nor disturb each
// other, and the DSN is refused outright if it names the production host, so a
// copy-pasted DATABASE_URL cannot turn a test run into a production write.
//
//	initdb -D /tmp/pg && pg_ctl -D /tmp/pg -o "-p 55432 -k /tmp" start
//	createdb -h /tmp -p 55432 hoppertest
//	HOPPER_TEST_PG_DSN='postgres://postgres@/hoppertest?host=/tmp&port=55432' go test ./...
func openDisposablePG(t *testing.T) *DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("HOPPER_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("HOPPER_TEST_PG_DSN not set (a disposable Postgres database)")
	}
	if strings.Contains(dsn, "hopper-db") {
		t.Fatal("HOPPER_TEST_PG_DSN names the production host; these tests write data")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	schema := fmt.Sprintf("t_%d", time.Now().UnixNano())
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect disposable pg: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close(ctx) //nolint:errcheck // test teardown
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") //nolint:errcheck // best-effort teardown
		admin.Close(ctx)                                         //nolint:errcheck // test teardown
	})

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	db, err := Open(ctx, dsn+sep+"search_path="+schema+",public", "hopper-test")
	if err != nil {
		t.Fatalf("open disposable pg: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate disposable pg: %v", err)
	}
	return db
}

// testBackends are the databases a twin-sensitive test runs against: SQLite
// always, and Postgres when HOPPER_TEST_PG_DSN is set (skipped otherwise) —
// for behavior both hand-written twins must agree on. Used as
//
//	for _, b := range testBackends {
//		t.Run(b.name, func(t *testing.T) { db := b.open(t); ... })
//	}
var testBackends = []struct {
	open func(*testing.T) *DB
	name string
}{
	{name: "sqlite", open: openTestDB},
	{name: "postgres", open: openDisposablePG},
}
