package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultStoreMaxConns is the verdict Store's default cap. pgx otherwise defaults MaxConns
// to NumCPU. On smaug that is 128, and this second pool (application_name
// hopper-load-store) opened 42 sessions and held them next to hopper-load and
// forager until hopper-db (max_connections 100) refused new ones, 2026-11-17.
// Four is the same budget poolSize gives every non-serving consumer. Each
// store call holds one connection for its transaction, so extra writers wait
// on the pool instead of owning a server slot.
//
// The cap is not taken from pool_max_conns. Load and serve-replica open the
// store on the same DSN as the serving pool, and that parameter is how the
// serving pool is widened. Honoring it here would hand the store the serving
// size again.
const defaultStoreMaxConns int32 = 4

// openStore opens the verdict tables in schema, on the database dsn names,
// creating them when the schema has none: a fresh install starts empty, and
// a migrated one (`hopper migrate`) already has them. Tables made from an
// older schema.sql are upgraded (store.Upgrade), unless the session is
// read-only.
func openStore(ctx context.Context, dsn, schema string, maxConns int32) (*store.Store, *pgxpool.Pool, error) {
	cfg, err := storePoolConfig(dsn, maxConns)
	if err != nil {
		return nil, nil, err
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	var exists bool
	err = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, pgx.Identifier{schema, "samples"}.Sanitize()).Scan(&exists)
	if err == nil && !exists {
		if _, err = pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+pgx.Identifier{schema}.Sanitize()); err == nil {
			_, err = pool.Exec(ctx, store.Schema)
		}
	}
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("store: schema %s: %w", schema, err)
	}
	st, err := store.New(pool)
	if err == nil {
		err = st.Upgrade(ctx)
	}
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return st, pool, nil
}

// openExistingStore opens the verdict tables in schema for a maintenance
// command. Unlike openStore it never creates them: a mistyped schema is an
// error, not a fresh empty store for the command to report success against.
func openExistingStore(ctx context.Context, dsn, schema string) (*store.Store, *pgxpool.Pool, error) {
	cfg, err := storePoolConfig(dsn, defaultStoreMaxConns)
	if err != nil {
		return nil, nil, err
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	var exists bool
	err = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, pgx.Identifier{schema, "samples"}.Sanitize()).Scan(&exists)
	if err == nil && !exists {
		err = errors.New("holds no verdict tables")
	}
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("store: schema %s: %w", schema, err)
	}
	st, err := store.New(pool)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return st, pool, nil
}

// storePoolConfig parses dsn and sizes the verdict-store pool. The
// application_name suffix keeps these sessions distinct from the serving pool
// in pg_stat_activity.
func storePoolConfig(dsn string, maxConns int32) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = string(cliAppName()) + "-store"
	cfg.MaxConns = maxConns
	cfg.MinConns = 0
	return cfg, nil
}
