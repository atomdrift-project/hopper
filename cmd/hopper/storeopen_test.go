package main

import (
	"os"
	"strings"
	"testing"
)

func TestStorePoolConfigCapsAtFour(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"hopper", "load"}

	cfg, err := storePoolConfig("postgres://hopper@hopper-db/hopper?sslmode=disable", defaultStoreMaxConns)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != defaultStoreMaxConns || cfg.MinConns != 0 {
		t.Fatalf("pool = max %d min %d, want max %d min 0", cfg.MaxConns, cfg.MinConns, defaultStoreMaxConns)
	}
	if got := cfg.ConnConfig.RuntimeParams["application_name"]; got != "hopper-load-store" {
		t.Fatalf("application_name = %q, want hopper-load-store", got)
	}
}

func TestStorePoolConfigIgnoresServingDSNCap(t *testing.T) {
	cfg, err := storePoolConfig("postgres://hopper@hopper-db/hopper?sslmode=disable&pool_max_conns=32", 16)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != 16 {
		t.Fatalf("store pool max = %d, want explicitly configured 16", cfg.MaxConns)
	}
}

// A maintenance command pointed at a schema with no verdict tables fails,
// and leaves no schema behind for the serving path to find later.
func TestOpenExistingStore(t *testing.T) {
	_, _, pool := verdictAPI(t)
	ctx := t.Context()
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn := strings.TrimSpace(os.Getenv("HOPPER_TEST_PG_DSN"))

	if _, p, err := openExistingStore(ctx, dsn, schema+"_typo"); err == nil {
		p.Close()
		t.Fatal("opened a schema with no verdict tables")
	}
	var created bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, schema+"_typo").Scan(&created); err != nil || created {
		t.Fatalf("typo schema created = %v, %v; want left alone", created, err)
	}

	st, p, err := openExistingStore(ctx, dsn, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := st.ReopenAcquisitions(ctx, nil, true, true); err != nil {
		t.Fatalf("dry-run reopen on the existing schema: %v", err)
	}
}
