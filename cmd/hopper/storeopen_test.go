package main

import (
	"os"
	"testing"
)

func TestStorePoolConfigCapsAtFour(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"hopper", "load"}

	cfg, err := storePoolConfig("postgres://hopper@hopper-db/hopper?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != storePoolMaxConns || cfg.MinConns != 0 {
		t.Fatalf("pool = max %d min %d, want max %d min 0", cfg.MaxConns, cfg.MinConns, storePoolMaxConns)
	}
	if got := cfg.ConnConfig.RuntimeParams["application_name"]; got != "hopper-load-store" {
		t.Fatalf("application_name = %q, want hopper-load-store", got)
	}
}

func TestStorePoolConfigIgnoresServingDSNCap(t *testing.T) {
	cfg, err := storePoolConfig("postgres://hopper@hopper-db/hopper?sslmode=disable&pool_max_conns=32")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxConns != storePoolMaxConns {
		t.Fatalf("pool_max_conns on the shared DSN widened the store pool to %d", cfg.MaxConns)
	}
}
