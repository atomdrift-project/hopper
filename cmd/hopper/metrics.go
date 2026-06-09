package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for the local metrics cache.
)

// metricsStore is a small, local SQLite-backed time series for the dashboard
// queue graphs. Historical queue depth cannot be reconstructed from the main
// sample table (a row carries only its current state, and the rescan set is
// defined by the live traits version), so the sampler snapshots the live
// counts here on a fixed interval. It is purely a cache: losing it costs only
// graph history, never sample data, so it lives in the OS cache directory and
// is independent of the primary Postgres/SQLite store.
type metricsStore struct {
	db *sql.DB
}

// queuePoint is one sampled snapshot of the work queues. Completed is the
// cumulative analyzed count (CountAnalyzed); per-interval throughput is the
// difference between consecutive points.
type queuePoint struct {
	T         time.Time
	Pending   int64
	Rescan    int64
	Completed int64
}

// metricsDBPath returns the path to the local metrics cache. HOPPER_METRICS_DB
// overrides it; otherwise it lives under the user cache dir, falling back to
// the temp dir when that is unavailable.
func metricsDBPath() string {
	if p := os.Getenv("HOPPER_METRICS_DB"); p != "" {
		return p
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "hopper", "queue-metrics.db")
}

// openMetricsStore opens (creating if needed) the local metrics cache at path
// and ensures its schema exists.
func openMetricsStore(ctx context.Context, path string) (*metricsStore, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("hopper: metrics cache dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("hopper: open metrics cache: %w", err)
	}
	// A single writer (the sampler) and the dashboard reader; one connection
	// avoids SQLite "database is locked" churn on a tiny table.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS queue_metrics (
			ts        INTEGER PRIMARY KEY,
			pending   INTEGER NOT NULL,
			rescan    INTEGER NOT NULL,
			completed INTEGER NOT NULL
		)`); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			slog.Debug("close metrics cache after schema error failed", "error", closeErr)
		}
		return nil, fmt.Errorf("hopper: metrics schema: %w", err)
	}
	return &metricsStore{db: db}, nil
}

// record appends one snapshot. ts is stored as whole UTC seconds, which also
// dedupes samples that land within the same second (INSERT OR REPLACE).
func (m *metricsStore) record(ctx context.Context, p queuePoint) error {
	_, err := m.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO queue_metrics (ts, pending, rescan, completed) VALUES (?, ?, ?, ?)`,
		p.T.UTC().Unix(), p.Pending, p.Rescan, p.Completed)
	if err != nil {
		return fmt.Errorf("hopper: record metric: %w", err)
	}
	return nil
}

// series returns snapshots at or after since, oldest first.
func (m *metricsStore) series(ctx context.Context, since time.Time) ([]queuePoint, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT ts, pending, rescan, completed FROM queue_metrics WHERE ts >= ? ORDER BY ts`,
		since.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("hopper: metric series: %w", err)
	}
	defer rows.Close() //nolint:errcheck // best-effort cleanup
	var out []queuePoint
	for rows.Next() {
		var ts int64
		var p queuePoint
		if err := rows.Scan(&ts, &p.Pending, &p.Rescan, &p.Completed); err != nil {
			return nil, fmt.Errorf("hopper: scan metric: %w", err)
		}
		p.T = time.Unix(ts, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// prune deletes snapshots older than before, bounding the cache size.
func (m *metricsStore) prune(ctx context.Context, before time.Time) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM queue_metrics WHERE ts < ?`, before.UTC().Unix())
	if err != nil {
		return fmt.Errorf("hopper: prune metrics: %w", err)
	}
	return nil
}

func (m *metricsStore) close() error { return m.db.Close() }
