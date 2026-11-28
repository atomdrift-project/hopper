package store

import "testing"

func TestParsePoolConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
		want int32
	}{
		{"url default", "postgres://hopper@hopper-db/hopper?sslmode=disable", DefaultMaxConns},
		{"keyword default", "host=hopper-db user=hopper dbname=hopper", DefaultMaxConns},
		{"url explicit", "postgres://hopper@hopper-db/hopper?sslmode=disable&pool_max_conns=32", 32},
		{"keyword explicit", "host=hopper-db pool_max_conns=2", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParsePoolConfig(tc.dsn)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.MaxConns != tc.want {
				t.Errorf("MaxConns = %d, want %d", cfg.MaxConns, tc.want)
			}
			if cfg.ConnConfig.RuntimeParams == nil {
				t.Error("RuntimeParams is nil; callers set application_name on it")
			}
		})
	}
	if _, err := ParsePoolConfig("postgres://%zz"); err == nil {
		t.Error("bad dsn parsed")
	}
}
