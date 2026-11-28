package store

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultMaxConns is the pool cap for a client of hopper's database whose DSN
// does not name pool_max_conns. The publisher (max_connections 100) has ~97
// slots for every service and operator combined.
//
// pgx's own default is max(4, NumCPU), which follows the box rather than the
// budget: 128 on smaug and on uruk-hai. That default has exhausted hopper-db
// twice. On 2026-11-17 hopper-load's store pool opened 42 sessions. On
// 2026-11-27 promoter, which opened its pool with plain pgxpool.ParseConfig,
// held 40 sessions next to forager's 32 and hopper-load's 24, and every
// non-superuser login (make replica included) got "remaining connection slots
// are reserved". A client that needs more says so in its DSN.
const DefaultMaxConns int32 = 4

// ParsePoolConfig parses dsn the way pgxpool.ParseConfig does, but caps the
// pool at DefaultMaxConns unless dsn names pool_max_conns. Every client that
// opens its own pool on hopper's database should start here instead of
// calling pgxpool.ParseConfig directly.
func ParsePoolConfig(dsn string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	if !strings.Contains(dsn, "pool_max_conns") {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	return cfg, nil
}
