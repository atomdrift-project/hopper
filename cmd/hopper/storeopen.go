package main

import (
	"context"
	"fmt"

	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openStore opens the verdict tables in schema, on the database dsn names,
// creating them when the schema has none: a fresh install starts empty, and
// a migrated one (`hopper migrate`) already has them.
func openStore(ctx context.Context, dsn, schema string) (*store.Store, *pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("store: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["application_name"] = string(cliAppName()) + "-store"
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
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return st, pool, nil
}
