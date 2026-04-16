package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // register sqlite3 driver
)

// cacheKey identifies a file by filesystem identity. Device+inode is unique
// across mount points; size+mtime detect content changes.
type cacheKey struct {
	dev   uint64
	inode uint64
	size  int64
	mtime int64 // UnixNano
}

// cacheEntry stores the SHA256 and whether the sample has been inserted into the
// samples DB. The inserted flag lets the scan skip batch inserts for files that
// haven't changed since the last successful run.
type cacheEntry struct {
	sha256   [32]byte
	inserted bool
}

// hashCache is a SQLite-persisted, memory-resident cache mapping file identity → sha256.
// On open it bulk-loads all rows into a map; lookups are O(1) with no I/O.
// New entries are buffered and flushed to SQLite in batches.
type hashCache struct {
	db      *sql.DB
	mem     map[cacheKey]cacheEntry // dev+inode+size+mtime → sha256 + inserted flag
	dirty   []dirtyEntry            // new entries pending write
	mu      sync.Mutex
	flushMu sync.Mutex
	queued  atomic.Bool
}

type dirtyEntry struct {
	key      cacheKey
	sha256   [32]byte
	inserted bool
}

const writeBatchSize = 5000

// openHashCache opens (or creates) a hash cache at the given path and
// preloads all entries into memory for O(1) lookups.
func openHashCache(ctx context.Context, path string) (*hashCache, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("hashcache: open: %w", err)
	}

	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS hash_cache (
		dev     INTEGER NOT NULL,
		inode   INTEGER NOT NULL,
		size    INTEGER NOT NULL,
		mtime   INTEGER NOT NULL,
		sha256  TEXT NOT NULL,
		PRIMARY KEY (dev, inode)
	)`)
	if err != nil {
		if closeErr := db.Close(); closeErr != nil {
			slog.Warn("hashcache: close after create failure", "error", closeErr)
		}
		return nil, fmt.Errorf("hashcache: create table: %w", err)
	}
	// Migration: add inserted column. Fails harmlessly if it already exists.
	//nolint:errcheck,gosec // ALTER TABLE fails harmlessly if column already exists.
	db.ExecContext(ctx, `ALTER TABLE hash_cache ADD COLUMN inserted INTEGER NOT NULL DEFAULT 0`)

	c := &hashCache{db: db, mem: make(map[cacheKey]cacheEntry)}
	if err := c.load(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			slog.Warn("hashcache: close after load failure", "error", closeErr)
		}
		return nil, err
	}
	return c, nil
}

// load bulk-reads all cache rows into the map.
func (c *hashCache) load(ctx context.Context) error {
	rows, err := c.db.QueryContext(ctx, `SELECT dev, inode, size, mtime, sha256, inserted FROM hash_cache`)
	if err != nil {
		return fmt.Errorf("hashcache: load: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			slog.Warn("hashcache: close rows", "error", closeErr)
		}
	}()

	for rows.Next() {
		var k cacheKey
		var shaHex string
		var ins int
		if err := rows.Scan(&k.dev, &k.inode, &k.size, &k.mtime, &shaHex, &ins); err != nil {
			return fmt.Errorf("hashcache: scan: %w", err)
		}
		var sha [32]byte
		if _, err := hex.Decode(sha[:], []byte(shaHex)); err != nil {
			return fmt.Errorf("hashcache: decode sha: %w", err)
		}
		c.mem[k] = cacheEntry{sha256: sha, inserted: ins != 0}
	}
	slog.Info("hash cache loaded", "entries", len(c.mem))
	return rows.Err()
}

// lookup checks the in-memory cache. Safe for concurrent use.
// Returns the hex-encoded sha256, whether the entry has been inserted into
// the samples DB, and whether the lookup was a hit.
func (c *hashCache) lookup(dev, inode uint64, size int64, mtime time.Time) (sha256Hex string, inserted bool, ok bool) {
	k := cacheKey{dev: dev, inode: inode, size: size, mtime: mtime.UnixNano()}
	c.mu.Lock()
	e, ok := c.mem[k]
	c.mu.Unlock()
	if !ok {
		return "", false, false
	}
	return hex.EncodeToString(e.sha256[:]), e.inserted, true
}

// store adds an entry to the in-memory cache and dirty buffer.
// Flushes to SQLite when the buffer reaches writeBatchSize.
func (c *hashCache) store(ctx context.Context, dev, inode uint64, size int64, mtime time.Time, sha256Hex string) {
	k := cacheKey{dev: dev, inode: inode, size: size, mtime: mtime.UnixNano()}
	var sha [32]byte
	if _, err := hex.Decode(sha[:], []byte(sha256Hex)); err != nil {
		slog.Warn("hashcache: decode digest", "error", err)
		return
	}

	c.mu.Lock()
	c.mem[k] = cacheEntry{sha256: sha}
	c.dirty = append(c.dirty, dirtyEntry{key: k, sha256: sha})
	shouldFlush := len(c.dirty) >= writeBatchSize
	c.mu.Unlock()

	if shouldFlush {
		c.requestFlush(ctx)
	}
}

// markInserted marks cache entries as successfully inserted into the samples DB.
// The flag is persisted on the next flush so future startups can skip re-inserting.
func (c *hashCache) markInserted(ctx context.Context, keys []cacheKey) {
	c.mu.Lock()
	for _, k := range keys {
		if e, ok := c.mem[k]; ok && !e.inserted {
			e.inserted = true
			c.mem[k] = e
			c.dirty = append(c.dirty, dirtyEntry{key: k, sha256: e.sha256, inserted: true})
		}
	}
	shouldFlush := len(c.dirty) >= writeBatchSize
	c.mu.Unlock()
	if shouldFlush {
		c.requestFlush(ctx)
	}
}

func (c *hashCache) requestFlush(ctx context.Context) {
	if !c.queued.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer c.queued.Store(false)
		c.flush(context.WithoutCancel(ctx))
	}()
}

// flush writes buffered entries to SQLite in a single transaction.
func (c *hashCache) flush(ctx context.Context) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()

	c.mu.Lock()
	batch := c.dirty
	c.dirty = nil
	c.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Warn("hashcache: begin tx", "error", err)
		return
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR REPLACE INTO hash_cache (dev, inode, size, mtime, sha256, inserted) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			slog.Warn("hashcache: rollback after prepare failure", "error", rollbackErr)
		}
		slog.Warn("hashcache: prepare", "error", err)
		return
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			slog.Warn("hashcache: close statement", "error", closeErr)
		}
	}()
	for _, e := range batch {
		ins := 0
		if e.inserted {
			ins = 1
		}
		if _, execErr := stmt.ExecContext(ctx,
			e.key.dev, e.key.inode, e.key.size, e.key.mtime, hex.EncodeToString(e.sha256[:]), ins); execErr != nil {
			slog.Warn("hashcache: exec", "error", execErr)
		}
	}
	if err := tx.Commit(); err != nil {
		slog.Warn("hashcache: commit", "error", err)
	}
}

// close flushes remaining entries and closes the database.
func (c *hashCache) close(ctx context.Context) {
	c.flush(ctx)
	if c.db != nil {
		if err := c.db.Close(); err != nil {
			slog.Warn("hashcache: close", "error", err)
		}
	}
}

// fileStat returns the device and inode numbers from an os.FileInfo via Stat_t.
func fileStat(info os.FileInfo) (dev, inode uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Dev, st.Ino
	}
	return 0, 0
}
