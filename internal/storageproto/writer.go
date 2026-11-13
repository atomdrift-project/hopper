// Package storageproto experiments with compact observation storage in an
// isolated local database. It is not imported by Hopper's production binaries.
package storageproto

import (
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// ErrCollision means a digest matched but the original string did not. No
// portion of the batch is committed in that case.
var ErrCollision = errors.New("storage prototype: path digest collision")

// Observation preserves Hopper's location metadata and synthetic locators.
type Observation struct {
	Mtime                                                              *time.Time
	SHA256, ParentSHA256, Path, Filename, Rel, Source, Feed, Ecosystem string
}

// Store owns one disposable schema. Pool is exposed for local measurements.
type Store struct {
	Pool   *pgxpool.Pool
	schema string
}

// Open refuses TCP hosts and any database other than hopper_schema_prototype.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(cfg.ConnConfig.Host, "/") || cfg.ConnConfig.Database != "hopper_schema_prototype" {
		return nil, errors.New("storage prototype requires a local Unix socket and database hopper_schema_prototype")
	}
	name := fmt.Sprintf("writer_%d", time.Now().UnixNano())
	cfg.ConnConfig.RuntimeParams["search_path"] = name + ",public"
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	s := &Store{Pool: pool, schema: name}
	if _, err = pool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{name}.Sanitize()); err != nil {
		pool.Close()
		return nil, err
	}
	if _, err = pool.Exec(ctx, schemaSQL); err != nil {
		_ = s.Close(ctx) //nolint:errcheck // preserve the schema initialization error
		return nil, err
	}
	return s, nil
}

// Close drops only the schema created by Open.
func (s *Store) Close(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{s.schema}.Sanitize()+" CASCADE")
	s.Pool.Close()
	return err
}

const stageDDL = `CREATE TEMP TABLE _staging(
 sha256 text,parent text,path text,filename text,rel text,source text,feed text,ecosystem text,mtime timestamptz,
 sha bytea,parent_sha bytea,parent_path text,relative_path text
) ON COMMIT DROP`

var stageColumns = []string{
	"sha256", "parent", "path", "filename", "rel", "source", "feed", "ecosystem", "mtime",
	"sha", "parent_sha", "parent_path", "relative_path",
}

func stage(ctx context.Context, tx pgx.Tx, observations []Observation) error {
	rows := make([][]any, len(observations))
	for i := range observations {
		o := &observations[i]
		sha, err := hex.DecodeString(o.SHA256)
		if err != nil || len(sha) != 32 {
			return errors.New("invalid sample SHA-256")
		}
		var parent []byte
		if o.ParentSHA256 != "" {
			parent, err = hex.DecodeString(o.ParentSHA256)
			if err != nil || len(parent) != 32 {
				return errors.New("invalid parent SHA-256")
			}
		}
		if o.Path == "" {
			return errors.New("empty observation path")
		}
		var prefix, relative any
		// Keep unresolvable and decoded locators verbatim. No offsets or transforms
		// are stripped, interpreted, or silently normalized.
		if n := strings.LastIndex(o.Path, "!!"); n > 0 && parent != nil {
			prefix, relative = o.Path[:n], o.Path[n+2:]
		}
		rows[i] = []any{
			strings.ToLower(o.SHA256), strings.ToLower(o.ParentSHA256), o.Path, o.Filename,
			o.Rel, o.Source, o.Feed, o.Ecosystem, o.Mtime, sha, parent, prefix, relative,
		}
	}
	if _, err := tx.Exec(ctx, stageDDL); err != nil {
		return err
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"_staging"}, stageColumns, pgx.CopyFromRows(rows))
	return err
}

// Write resolves each distinct identity and locator in bulk. Inserts and
// corrections commit atomically; unchanged dictionary entries are never updated.
func (s *Store) Write(ctx context.Context, observations []Observation) (int64, error) {
	if len(observations) == 0 {
		return 0, nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	if err := stage(ctx, tx, observations); err != nil {
		return 0, err
	}
	// The common repeat walk needs no dictionary inserts or resolution. Verify
	// exact reconstructed paths as well as metadata, so digest collisions cannot
	// turn a different observation into an apparent no-op.
	var unchanged bool
	if err := tx.QueryRow(ctx, unchangedBatchSQL).Scan(&unchanged); err != nil {
		return 0, err
	}
	if unchanged {
		return 0, tx.Commit(ctx)
	}
	for _, q := range []string{resolveSamplesSQL, resolvePathsSQL, resolveParentsSQL} {
		if _, err = tx.Exec(ctx, q); err != nil {
			return 0, err
		}
	}
	// Resolve in a separate statement after INSERT ... DO NOTHING. At READ
	// COMMITTED this sees dictionary rows committed by competing writers, even
	// when those rows were invisible to the INSERT's initial snapshot. Exact
	// string matching leaves missing IDs on collisions, which we reject below.
	if _, err = tx.Exec(ctx, resolveLocationsSQL); err != nil {
		return 0, err
	}
	var collision bool
	if err := tx.QueryRow(ctx, checkLocationsSQL).Scan(&collision); err != nil {
		return 0, err
	}
	if collision {
		return 0, ErrCollision
	}
	tag, err := tx.Exec(ctx, writeLocationsSQL)
	if err != nil {
		return 0, err
	}
	// Also verify after the upsert: a competing insert may have won the unique
	// key with a different path after our initial collision check.
	if err := tx.QueryRow(ctx, checkLocationsSQL).Scan(&collision); err != nil {
		return 0, err
	}
	if collision {
		return 0, ErrCollision
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// WriteLegacy runs Hopper's current location statement against the matching
// baseline tables, including the same staging and batched identity-resolution
// work. It deliberately excludes analysis/label updates on both sides.
func (s *Store) WriteLegacy(ctx context.Context, observations []Observation, locationSQL string) (int64, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback
	if err := stage(ctx, tx, observations); err != nil {
		return 0, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO samples(sha256)
 SELECT sha FROM (SELECT sha256 AS sha FROM _staging UNION SELECT parent FROM _staging WHERE parent<>'') d
 WHERE NOT EXISTS(SELECT 1 FROM samples s WHERE s.sha256=d.sha) ORDER BY sha ON CONFLICT DO NOTHING`); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, locationSQL)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
