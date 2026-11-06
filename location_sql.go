package hopper

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// locationRows is the read-only intersection of sql.Rows and pgx.Rows.
type locationRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func locationSQLiteSQL(query string) string {
	return strings.NewReplacer("$1", "?1", "$2", "?2", "$3", "?3", "$4", "?4", "$5", "?5", " FOR UPDATE", "").Replace(query)
}

func (db *DB) queryLocations(ctx context.Context, query string, args []any, scan func(locationRows) error) error {
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
	rows, err := db.lite.QueryContext(ctx, locationSQLiteSQL(query), args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // read-only query
	if err := scan(rows); err != nil {
		return err
	}
	return rows.Err()
}

type locationSQLTx struct {
	exec  func(string, ...any) error
	query func(string, []any, func(locationRows) error) error
}

func pgLocationSQLTx(ctx context.Context, tx pgx.Tx) locationSQLTx {
	return locationSQLTx{
		exec: func(q string, args ...any) error { _, err := tx.Exec(ctx, q, args...); return err },
		query: func(q string, args []any, scan func(locationRows) error) error {
			rows, err := tx.Query(ctx, q, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			if err := scan(rows); err != nil {
				return err
			}
			return rows.Err()
		},
	}
}

func sqliteLocationSQLTx(ctx context.Context, tx *sql.Tx) locationSQLTx {
	return locationSQLTx{
		exec: func(q string, args ...any) error {
			_, err := tx.ExecContext(ctx, locationSQLiteSQL(q), args...)
			return err
		},
		query: func(q string, args []any, scan func(locationRows) error) error {
			rows, err := tx.QueryContext(ctx, locationSQLiteSQL(q), args...)
			if err != nil {
				return err
			}
			defer rows.Close() //nolint:errcheck // read-only query
			if err := scan(rows); err != nil {
				return err
			}
			return rows.Err()
		},
	}
}

func (db *DB) locationTransaction(ctx context.Context, fn func(locationSQLTx) error) error {
	if db.pool != nil {
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck // committed below
		if err := fn(pgLocationSQLTx(ctx, tx)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // committed below
	if err := fn(sqliteLocationSQLTx(ctx, tx)); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) locationTimestamp() any {
	if db.pool == nil {
		return now()
	}
	return time.Now().UTC()
}

// The parent row is the handoff between move completion and delayed member
// writes. An ingest that commits after the final move sweep waits here, then
// observes its retirement record and repairs the old prefix before returning.
func lockLocationParent(tx locationSQLTx, sha string) error {
	return tx.query(`SELECT sha256 FROM samples WHERE sha256 = $1 FOR UPDATE`, []any{sha}, func(rows locationRows) error {
		for rows.Next() {
			var sha string
			if err := rows.Scan(&sha); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

func rebaseMemberSQL(tx locationSQLTx, sha, oldPath, newPath, where string, stamp any) error {
	if oldPath == newPath {
		return nil
	}
	oldPrefix, newPrefix := oldPath+"!!", newPath+"!!"
	if where == "" {
		where = `parent_sha256 = $1 AND substr(path,1,length($2)) = $2`
	}
	if err := tx.exec(`INSERT INTO sample_locations
  (sha256,path,parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at)
  SELECT sha256,$3 || substr(path,length($2)+1),parent_sha256,rel,filename,source,feed,ecosystem,mtime,first_seen_at,last_seen_at
  FROM sample_locations WHERE `+where+` ON CONFLICT DO NOTHING`, sha, oldPrefix, newPrefix); err != nil {
		return err
	}
	if err := tx.exec(`UPDATE samples SET path = $3 || substr(samples.path,length($2)+1), updated_at = $4
  FROM (SELECT sha256, path FROM sample_locations WHERE `+where+`) old
  WHERE samples.sha256 = old.sha256 AND samples.path = old.path`, sha, oldPrefix, newPrefix, stamp); err != nil {
		return err
	}
	return tx.exec(`DELETE FROM sample_locations WHERE `+where, sha, oldPrefix)
}

// rebaseLocationMembers runs before retiring the physical move's retry record.
// Selection uses the existing parent index; writes use bounded primary-key sets.
// The literal prefix comparison deliberately gives '%' and '_' no special meaning.
func (db *DB) rebaseLocationMembers(ctx context.Context, sha, oldPath, newPath string) error {
	if oldPath == newPath {
		return nil
	}
	_, recorded, err := db.TopLevelLocationsRecorded(ctx, sha, oldPath, newPath)
	if err != nil {
		return err
	}
	if !recorded {
		return errors.New("hopper: member rebase destination is not recorded")
	}
	oldPrefix := oldPath + "!!"
	for {
		var ids, shas []string
		err := db.queryLocations(ctx, `SELECT id, sha256 FROM sample_locations
   WHERE parent_sha256 = $1 AND substr(path, 1, length($2)) = $2 LIMIT 1000`, []any{sha, oldPrefix}, func(rows locationRows) error {
			for rows.Next() {
				var id int64
				var child string
				if err := rows.Scan(&id, &child); err != nil {
					return err
				}
				ids = append(ids, strconv.FormatInt(id, 10))
				shas = append(shas, child)
			}
			return rows.Err()
		})
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		// IDs came from the database, formatted as decimal integers, never from paths.
		where := `id IN (` + strings.Join(ids, ",") + `) AND parent_sha256 = $1 AND substr(path,1,length($2)) = $2`
		err = db.locationTransaction(ctx, func(tx locationSQLTx) error {
			return rebaseMemberSQL(tx, sha, oldPath, newPath, where, db.locationTimestamp())
		})
		if err != nil {
			return err
		}
		for _, child := range shas {
			db.forgetSHA(child)
		}
	}
}

// memberOrigin identifies one outer path used by an ingest batch. Deduplication
// here makes the cost per archive, rather than per member.
type memberOrigin struct{ sha, path string }

func (db *DB) reconcileSampleLocations(ctx context.Context, samples []*Sample) error {
	var origins []memberOrigin
	for _, s := range samples {
		if s.Parent != "" {
			if outer := ArchivePathOf(s.Path); outer != "" {
				origins = append(origins, memberOrigin{s.Parent, outer})
			}
		}
	}
	return db.reconcileRetiredMemberPaths(ctx, origins)
}

func (db *DB) locationRecorded(tx locationSQLTx, sha, path string) (bool, error) {
	predicate := `sha256 = $1 AND path = $2 AND parent_sha256 = ''`
	if db.pool != nil {
		predicate += ` AND path_key(path) = path_key($2)`
	}
	var found bool
	err := tx.query(`SELECT EXISTS(SELECT 1 FROM sample_locations WHERE `+predicate+`)`, []any{sha, path}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&found)
		}
		return rows.Err()
	})
	return found, err
}

// A result may have been built before its parent moved. Follow only recorded
// moves of that exact outer path, preserving observations at a restored source.
func (db *DB) reconcileRetiredMemberPaths(ctx context.Context, origins []memberOrigin) error {
	seen := map[memberOrigin]bool{}
	for _, origin := range origins {
		if seen[origin] {
			continue
		}
		seen[origin] = true
		var changed []string
		err := db.locationTransaction(ctx, func(tx locationSQLTx) error {
			if err := lockLocationParent(tx, origin.sha); err != nil {
				return err
			}
			current, err := db.activeMoveSuccessor(tx, origin)
			if err != nil || current == "" || current == origin.path {
				return err
			}
			err = tx.query(`SELECT sha256 FROM sample_locations
    WHERE parent_sha256 = $1 AND substr(path,1,length($2)) = $2`,
				[]any{origin.sha, origin.path + "!!"}, func(rows locationRows) error {
					for rows.Next() {
						var child string
						if err := rows.Scan(&child); err != nil {
							return err
						}
						changed = append(changed, child)
					}
					return rows.Err()
				})
			if err != nil || len(changed) == 0 {
				return err
			}
			return rebaseMemberSQL(tx, origin.sha, origin.path, current, "", db.locationTimestamp())
		})
		if err != nil {
			return err
		}
		for _, sha := range changed {
			db.forgetSHA(sha)
		}
	}
	return nil
}

func (db *DB) activeMoveSuccessor(tx locationSQLTx, origin memberOrigin) (string, error) {
	current := origin.path
	visited := map[string]bool{}
	for {
		if visited[current] {
			return "", fmt.Errorf("hopper: cyclic location move history for %s", origin.sha)
		}
		visited[current] = true
		active, err := db.locationRecorded(tx, origin.sha, current)
		if err != nil {
			return "", err
		}
		if active {
			return current, nil
		}
		var next string
		err = tx.query(`SELECT successor_path FROM sample_location_history
   WHERE sha256 = $1 AND path = $2 AND parent_sha256 = '' AND reason = 'move'
   ORDER BY retired_at DESC, id DESC LIMIT 1`, []any{origin.sha, current}, func(rows locationRows) error {
			if rows.Next() {
				return rows.Scan(&next)
			}
			return rows.Err()
		})
		if err != nil || next == "" {
			return "", err
		}
		current = next
	}
}
