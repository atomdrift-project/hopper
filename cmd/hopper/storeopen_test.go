package main

import (
	"os"
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
