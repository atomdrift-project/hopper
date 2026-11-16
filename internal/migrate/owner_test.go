package migrate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A migration run as a superuser leaves the new schema to the role that owns
// the legacy tables, as hopper's services connect as it: that role can then
// read and write every new table, type and function.
//
//	HOPPER_TEST_PG_DSN="$(scripts/test-pg.sh)" go test -run Owner ./internal/migrate
func TestOwnerGoesToTheLegacyTablesOwner(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("HOPPER_TEST_PG_DSN"))
	if dsn == "" || strings.Contains(dsn, "hopper-db") {
		t.Skip("HOPPER_TEST_PG_DSN (a disposable database, as a superuser) is needed")
	}
	ctx := t.Context()
	suffix := time.Now().UnixNano()
	legacy, to, role := fmt.Sprintf("legacy_%d", suffix), fmt.Sprintf("verdict_%d", suffix), fmt.Sprintf("owner_%d", suffix)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = to
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(ctx)
		for _, stmt := range []string{"DROP SCHEMA IF EXISTS " + to + " CASCADE", "DROP SCHEMA IF EXISTS " + legacy + " CASCADE", "DROP ROLE IF EXISTS " + role} {
			if _, err := pool.Exec(ctx, stmt); err != nil {
				t.Errorf("%s: %v", stmt, err)
			}
		}
		pool.Close()
	})
	for _, stmt := range []string{
		"CREATE ROLE " + role,
		"CREATE SCHEMA " + legacy,
		"CREATE TABLE " + legacy + ".samples (id bigint)",
		"ALTER TABLE " + legacy + ".samples OWNER TO " + role,
		"CREATE SCHEMA " + to,
		store.Schema,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%.60s: %v", stmt, err)
		}
	}
	m := &migration{pool: pool, from: pgx.Identifier{legacy}.Sanitize()}
	if err := m.owner(ctx); err != nil {
		t.Fatal(err)
	}
	var others []string
	rows, err := pool.Query(ctx, `SELECT 'schema ' || nspname FROM pg_namespace WHERE nspname = $1 AND nspowner::regrole::text <> $2
		UNION ALL SELECT 'relation ' || relname FROM pg_class WHERE relnamespace = $1::regnamespace AND relowner::regrole::text <> $2
		UNION ALL SELECT 'type ' || typname FROM pg_type WHERE typnamespace = $1::regnamespace AND typtype = 'e' AND typowner::regrole::text <> $2
		UNION ALL SELECT 'function ' || proname FROM pg_proc WHERE pronamespace = $1::regnamespace AND proowner::regrole::text <> $2`, to, role)
	if err != nil {
		t.Fatal(err)
	}
	if others, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	if len(others) > 0 {
		t.Errorf("not the legacy owner's: %v", others)
	}
	// Run again, it changes nothing and fails nothing.
	if err := m.owner(ctx); err != nil {
		t.Errorf("a second run: %v", err)
	}
}
