package main

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestForceReadOnlyDSN round-trips the rewritten DSN through pgx's own parser,
// because the failure mode is in how pgx decodes the query string (pgx >= 5.11
// passes '+' through literally, unlike net/url), not in what we build.
func TestForceReadOnlyDSN(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "bare",
			dsn:  "postgres://hopper@127.0.0.1:5432/hopper",
			want: "-c default_transaction_read_only=on",
		},
		{
			name: "preserves existing options",
			dsn:  "postgresql://hopper:pw@db.example/hopper?sslmode=disable&options=-c%20statement_timeout%3D5s",
			want: "-c statement_timeout=5s -c default_transaction_read_only=on",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := forceReadOnlyDSN(tc.dsn)
			if err != nil {
				t.Fatalf("forceReadOnlyDSN(%q): %v", tc.dsn, err)
			}
			cfg, err := pgconn.ParseConfig(out)
			if err != nil {
				t.Fatalf("pgconn.ParseConfig(%q): %v", out, err)
			}
			if got := cfg.RuntimeParams["options"]; got != tc.want {
				t.Fatalf("options from %q:\n got %q\nwant %q", out, got, tc.want)
			}
		})
	}

	if _, err := forceReadOnlyDSN("host=localhost dbname=hopper"); err == nil {
		t.Fatal("keyword/value DSN accepted; want error")
	}
}
