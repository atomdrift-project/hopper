package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
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

// hashCache is a SQLite-persisted, memory-resident cache mapping file identity → sha256.
// On open it bulk-loads all rows into a map; lookups are O(1) with no I/O.
// New entries are buffered and flushed to SQLite in batches.
type hashCache struct {
	db    *sql.DB
	mu    sync.Mutex
	mem   map[cacheKey][32]byte // dev+inode+size+mtime → raw sha256
	dirty []dirtyEntry          // new entries pending write
}

type dirtyEntry struct {
	key    cacheKey
	sha256 [32]byte
}

const writeBatchSize = 1000

// openHashCache opens (or creates) a hash cache at the given path and
// preloads all entries into memory for O(1) lookups.
func openHashCache(path string) (*hashCache, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("hashcache: open: %w", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS hash_cache (
		dev     INTEGER NOT NULL,
		inode   INTEGER NOT NULL,
		size    INTEGER NOT NULL,
		mtime   INTEGER NOT NULL,
		sha256  TEXT NOT NULL,
		PRIMARY KEY (dev, inode)
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("hashcache: create table: %w", err)
	}

	c := &hashCache{db: db, mem: make(map[cacheKey][32]byte)}
	if err := c.load(); err != nil {
		db.Close()
		return nil, err
	}
	return c, nil
}

// load bulk-reads all cache rows into the map.
func (c *hashCache) load() error {
	rows, err := c.db.Query(`SELECT dev, inode, size, mtime, sha256 FROM hash_cache`)
	if err != nil {
		return fmt.Errorf("hashcache: load: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var k cacheKey
		var shaHex string
		if err := rows.Scan(&k.dev, &k.inode, &k.size, &k.mtime, &shaHex); err != nil {
			return fmt.Errorf("hashcache: scan: %w", err)
		}
		var sha [32]byte
		hex.Decode(sha[:], []byte(shaHex)) //nolint:errcheck // trusted DB data
		c.mem[k] = sha
	}
	slog.Info("hash cache loaded", "entries", len(c.mem))
	return rows.Err()
}

// lookup checks the in-memory cache. Safe for concurrent use.
// Returns the hex-encoded sha256 and true on hit.
func (c *hashCache) lookup(dev, inode uint64, size int64, mtime time.Time) (string, bool) {
	k := cacheKey{dev: dev, inode: inode, size: size, mtime: mtime.UnixNano()}
	c.mu.Lock()
	sha, ok := c.mem[k]
	c.mu.Unlock()
	if !ok {
		return "", false
	}
	return hex.EncodeToString(sha[:]), true
}

// store adds an entry to the in-memory cache and dirty buffer.
// Flushes to SQLite when the buffer reaches writeBatchSize.
func (c *hashCache) store(dev, inode uint64, size int64, mtime time.Time, sha256Hex string) {
	k := cacheKey{dev: dev, inode: inode, size: size, mtime: mtime.UnixNano()}
	var sha [32]byte
	hex.Decode(sha[:], []byte(sha256Hex)) //nolint:errcheck // just computed

	c.mu.Lock()
	c.mem[k] = sha
	c.dirty = append(c.dirty, dirtyEntry{key: k, sha256: sha})
	shouldFlush := len(c.dirty) >= writeBatchSize
	c.mu.Unlock()

	if shouldFlush {
		c.flush()
	}
}

// flush writes buffered entries to SQLite in a single transaction.
func (c *hashCache) flush() {
	c.mu.Lock()
	batch := c.dirty
	c.dirty = nil
	c.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	tx, err := c.db.Begin()
	if err != nil {
		slog.Warn("hashcache: begin tx", "error", err)
		return
	}
	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO hash_cache (dev, inode, size, mtime, sha256) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		slog.Warn("hashcache: prepare", "error", err)
		return
	}
	for _, e := range batch {
		stmt.Exec(e.key.dev, e.key.inode, e.key.size, e.key.mtime, hex.EncodeToString(e.sha256[:])) //nolint:errcheck,gosec
	}
	stmt.Close() //nolint:errcheck
	if err := tx.Commit(); err != nil {
		slog.Warn("hashcache: commit", "error", err)
	}
}

// close flushes remaining entries and closes the database.
func (c *hashCache) close() {
	c.flush()
	if c.db != nil {
		c.db.Close()
	}
}

// fileStat returns the device and inode numbers from an os.FileInfo via Stat_t.
func fileStat(info os.FileInfo) (dev, inode uint64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino
	}
	return 0, 0
}
