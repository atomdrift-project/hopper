package hopper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PurgatoryMigrationStats counts completed operations, or planned operations
// during a dry run. Failed locations remain catalogued for the next attempt.
type PurgatoryMigrationStats struct {
	Locations int
	Members   int
	Labels    int
	Failed    int
}

// MigratePurgatory relocates the legacy pool and renames its classification.
// Run on the full corpus host with ingestion and other movers paused. Each
// file uses MoveLocation's durable retry record; member path changes and label
// renames commit in short transactions. Re-running resumes unfinished work.
// Existing attribution, skip state, and audit history are preserved. No sample
// is inferred to be dual-use: that requires an explicit later ruling.
func (db *DB) MigratePurgatory(ctx context.Context, dataRoot string, apply bool) (PurgatoryMigrationStats, error) {
	var stats PurgatoryMigrationStats
	root, err := filepath.Abs(dataRoot)
	if err != nil {
		return stats, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return stats, err
	}
	if !info.IsDir() {
		return stats, errors.New("hopper: migration data root must be a directory")
	}
	for _, members := range []bool{false, true} {
		var after int64
		for {
			batch, err := db.purgatoryMigrationBatch(ctx, after, members, false)
			if err != nil {
				return stats, err
			}
			if len(batch) == 0 {
				break
			}
			for _, item := range batch {
				after = item.id
				if err := ctx.Err(); err != nil {
					return stats, err
				}
				if err := db.migratePurgatoryLocation(ctx, root, item, apply); err != nil {
					stats.Failed++
					slog.Error("purgatory migration location failed", "path", item.path, "sha256", item.sha, "error", err)
					continue
				}
				if members {
					stats.Members++
				} else {
					stats.Locations++
				}
			}
		}
		if stats.Failed != 0 {
			return stats, fmt.Errorf("hopper: %d legacy locations could not be migrated; fix the reported paths and re-run", stats.Failed)
		}
	}
	// Rename labels last, including members and rows whose only location lives
	// outside purgatory/. CAS predicates preserve any newer explicit ruling.
	var after int64
	for {
		batch, err := db.purgatoryMigrationBatch(ctx, after, false, true)
		if err != nil {
			return stats, err
		}
		if len(batch) == 0 {
			return stats, nil
		}
		for _, item := range batch {
			after = item.id
			if apply {
				if err := db.renamePurgatoryLabel(ctx, item.sha); err != nil {
					return stats, err
				}
			}
			stats.Labels++
		}
	}
}

type purgatoryMigrationItem struct {
	sha    string
	path   string
	parent string
	id     int64
}

// purgatoryMigrationRows is the read-only intersection of sql.Rows and pgx.Rows.
type purgatoryMigrationRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func (db *DB) queryPurgatoryMigration(ctx context.Context, query string, args []any, scan func(purgatoryMigrationRows) error) error {
	if db.pool != nil {
		rows, err := db.pool.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if err := scan(rows); err != nil {
			return err
		}
		return rows.Err()
	}
	rows, err := db.lite.QueryContext(ctx, purgatorySQLiteSQL(query), args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // read-only query
	if err := scan(rows); err != nil {
		return err
	}
	return rows.Err()
}

// Numbered SQLite parameters preserve repeated/out-of-order PG arguments.
func purgatorySQLiteSQL(query string) string {
	return strings.NewReplacer("$1", "?1", "$2", "?2", "$3", "?3", "$4", "?4",
		"path LIKE 'purgatory/%'", "path GLOB 'purgatory/*'").Replace(query)
}

func (db *DB) purgatoryMigrationBatch(ctx context.Context, after int64, members, labels bool) ([]purgatoryMigrationItem, error) {
	query := `SELECT id, sha256, path, parent_sha256 FROM sample_locations
		WHERE path LIKE 'purgatory/%' AND id > $1 AND parent_sha256 = '' ORDER BY id LIMIT 1000`
	if members {
		query = strings.Replace(query, "parent_sha256 = ''", "parent_sha256 <> ''", 1)
	}
	if labels {
		query = `SELECT id, sha256, path, parent FROM samples
			WHERE label = 'purgatory' AND id > $1 ORDER BY id LIMIT 1000`
	}
	var batch []purgatoryMigrationItem
	err := db.queryPurgatoryMigration(ctx, query, []any{after}, func(rows purgatoryMigrationRows) error {
		for rows.Next() {
			var item purgatoryMigrationItem
			if err := rows.Scan(&item.id, &item.sha, &item.path, &item.parent); err != nil {
				return err
			}
			batch = append(batch, item)
		}
		return rows.Err()
	})
	return batch, err
}

func (db *DB) migratePurgatoryLocation(ctx context.Context, root string, item purgatoryMigrationItem, apply bool) error {
	newRel := PoolInconclusive + strings.TrimPrefix(item.path, PoolPurgatory)
	if item.parent != "" {
		return db.migratePurgatoryMember(ctx, root, item, newRel, apply)
	}
	sample, err := db.SampleBySHA256(ctx, item.sha)
	if err != nil {
		return err
	}
	if CanonicalLabel(sample.Label) != labelInconclusive {
		return fmt.Errorf("sample is now %q; relocate it with hopper mv before retrying", sample.Label)
	}
	if apply {
		result, err := db.MoveLocation(ctx, MoveLocationOptions{
			DataRoot: root, SHA256: item.sha, OldPath: item.path, NewPath: newRel,
		})
		if err == nil && !result.Relocated {
			return errors.New("hopper: migration move did not record its destination")
		}
		return err
	}
	// The preview also checks that at least one end contains the expected
	// bytes, including a destination published by an interrupted earlier run.
	return verifyPurgatoryMigrationFile(root, item.path, newRel, item.sha, false)
}

func verifyPurgatoryMigrationFile(root, oldRel, newRel, sha string, destinationOnly bool) error {
	_, newAbs, err := resolveMovePath(root, newRel)
	if err != nil {
		return err
	}
	if destinationOnly {
		return verifyMoveFile(newAbs, sha)
	}
	_, oldAbs, err := resolveMovePath(root, oldRel)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(oldAbs); err == nil {
		if err := verifyMoveFile(oldAbs, sha); err != nil {
			return err
		}
		// An existing destination must match too; a real move never clobbers it.
		if _, err := os.Lstat(newAbs); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return verifyMoveFile(newAbs, sha)
}

func (db *DB) migratePurgatoryMember(ctx context.Context, root string, item purgatoryMigrationItem, newRel string, apply bool) error {
	oldArchive, _, ok := strings.Cut(item.path, "!!")
	if !ok {
		return errors.New("member location has no containing archive path; repair its location before retrying")
	}
	newArchive := PoolInconclusive + strings.TrimPrefix(oldArchive, PoolPurgatory)
	// After a crash the old top-level row may already be retired. Its move
	// history proves which bytes back the new containing-archive path.
	var sha string
	err := db.queryPurgatoryMigration(ctx, `
		SELECT sha256 FROM sample_locations WHERE path = $1 AND parent_sha256 = ''
		UNION
		SELECT sha256 FROM sample_location_history
		 WHERE path = $1 AND parent_sha256 = '' AND successor_path = $2 AND reason = 'move'`,
		[]any{oldArchive, newArchive}, func(rows purgatoryMigrationRows) error {
			for rows.Next() {
				var found string
				if err := rows.Scan(&found); err != nil {
					return err
				}
				if sha != "" && sha != found {
					return errors.New("containing archive path has conflicting content hashes")
				}
				sha = found
			}
			return rows.Err()
		})
	if err != nil {
		return err
	}
	if sha == "" {
		return errors.New("containing archive is not catalogued at either end of the migration")
	}
	if err := verifyPurgatoryMigrationFile(root, oldArchive, newArchive, sha, apply); err != nil {
		return fmt.Errorf("verify containing archive: %w", err)
	}
	if !apply {
		return nil
	}
	err = db.purgatoryMigrationTransaction(ctx, func(exec func(string, ...any) error) error {
		if err := exec(`INSERT INTO sample_location_history
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
			 mtime, first_seen_at, last_seen_at, reason, successor_path)
			SELECT sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
			       mtime, first_seen_at, last_seen_at, 'purgatory-migration', $2
			FROM sample_locations WHERE id = $1`, item.id, newRel); err != nil {
			return err
		}
		if err := exec(`INSERT INTO sample_locations
			(sha256, path, parent_sha256, rel, filename, source, feed, ecosystem,
			 mtime, first_seen_at, last_seen_at)
			SELECT sha256, $2, parent_sha256, rel, filename, source, feed, ecosystem,
			       mtime, first_seen_at, last_seen_at FROM sample_locations WHERE id = $1
			ON CONFLICT (sha256, path) DO NOTHING`, item.id, newRel); err != nil {
			return err
		}
		if err := exec(`UPDATE samples SET path = $1, updated_at = $4
			WHERE sha256 = $2 AND path = $3`, newRel, item.sha, item.path, db.purgatoryMigrationTime()); err != nil {
			return err
		}
		return exec(`DELETE FROM sample_locations WHERE id = $1`, item.id)
	})
	if err == nil {
		db.forgetSHA(item.sha)
	}
	return err
}

func (db *DB) purgatoryMigrationTime() any {
	t := time.Now().UTC()
	if db.pool != nil {
		return t
	}
	return t.Format(time.RFC3339Nano)
}

func (db *DB) renamePurgatoryLabel(ctx context.Context, sha string) error {
	err := db.purgatoryMigrationTransaction(ctx, func(exec func(string, ...any) error) error {
		if err := exec(`INSERT INTO label_events
			(sha256, from_label, to_label, from_skip, to_skip, reason)
			SELECT sha256, label, 'inconclusive', skip, skip, 'purgatory-migration'
			FROM samples WHERE sha256 = $1 AND label = 'purgatory'`, sha); err != nil {
			return err
		}
		return exec(`UPDATE samples SET label = 'inconclusive', updated_at = $2
			WHERE sha256 = $1 AND label = 'purgatory'`, sha, db.purgatoryMigrationTime())
	})
	if err == nil {
		db.forgetSHA(sha)
	}
	return err
}

func (db *DB) purgatoryMigrationTransaction(ctx context.Context, fn func(func(string, ...any) error) error) error {
	if db.pool != nil {
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck // committed below on success
		if err := fn(func(query string, args ...any) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // committed below on success
	if err := fn(func(query string, args ...any) error {
		_, err := tx.ExecContext(ctx, purgatorySQLiteSQL(query), args...)
		return err
	}); err != nil {
		return err
	}
	return tx.Commit()
}
