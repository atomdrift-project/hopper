package main

import (
	"container/list"
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"codeberg.org/atomdrift/hopper"
	"golang.org/x/sync/singleflight"
)

// extractCache keeps decompressed copies of compressed-tar archive parents on
// disk so the members of one archive are decompressed once, not once per member
// request. tar.xz/tar.zst/tar.gz/tar.bz2 are not seekable, so without this every
// GET /api/file member fetch re-runs the whole (CPU-bound) decompressor from
// byte 0 — O(N×M) work for N members of an M-byte archive, which saturates the
// extraction slots and times clients out. The cache makes the steady state O(M):
// the first member pays the decompression, the rest stream straight off the
// resulting seekable tar with no slot contention.
//
// Entries are reference-counted so an in-use file is never removed mid-read.
// Each decompressed tar is unlinked the moment it is built, so its disk is
// reclaimed when the last reader closes it (or the process exits) and a crash
// leaves nothing behind to clean up.
type extractCache struct {
	group singleflight.Group // collapses concurrent builds of the same parent
	// gate bounds concurrent heavy builds (it holds an extraction slot for the
	// decompression). Cache hits never call it, so many members of a warm archive
	// serve in parallel. release returns the slot. Both may be nil (no gating).
	gate     func(context.Context) error
	release  func()
	byID     map[string]*extractEntry
	lru      *list.List // *extractEntry, front = most recently used
	dir      string     // scratch directory the build temp files live in
	mu       sync.Mutex
	maxBytes int64 // soft total-disk budget; LRU-evicted once exceeded
	perEntry int64 // largest decompressed tar to cache; bigger falls back
	used     int64
}

// extractEntry is one decompressed parent tar held open (and already unlinked).
type extractEntry struct {
	file *os.File      // the decompressed tar; ReadAt is safe for concurrent readers
	elem *list.Element // position in lru
	sha  string
	size int64
	refs int  // in-flight readers; the entry can be removed only at 0
	dead bool // evicted: close+remove once refs reaches 0
}

// cachedTar is a shared, seekable reader over one decompressed parent tar. done
// MUST be called when the caller finishes reading so the reference is dropped
// and an evicted entry's disk can be reclaimed.
type cachedTar struct {
	r    io.ReaderAt
	done func()
	size int64
}

// errCacheTooLarge signals the decompressed tar exceeded the per-entry budget,
// and errCacheDisabled that no cache is configured. Both tell the caller to
// serve the member by direct streaming instead.
var (
	errCacheTooLarge = errors.New("archive too large to cache")
	errCacheDisabled = errors.New("extract cache disabled")
)

// newExtractCache prepares the cache directory. A zero dir or non-positive
// budget returns a nil *extractCache, which is a valid, disabled cache: its
// methods are nil-safe and readerAt reports errCacheDisabled so callers fall
// back to direct streaming.
func newExtractCache(dir string, maxBytes, perEntry int64, gate func(context.Context) error, release func()) (*extractCache, error) {
	if dir == "" || maxBytes <= 0 {
		return nil, nil //nolint:nilnil // a nil cache is the explicit "disabled" value; methods are nil-safe
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// A cached entry must fit the total budget; otherwise it would be evicted the
	// instant it is built (used > budget, refs 0) and never serve a hit. Clamp so
	// an over-budget archive is rejected up front (errCacheTooLarge → direct
	// stream) rather than rebuilt forever.
	if perEntry <= 0 || perEntry > maxBytes {
		perEntry = maxBytes
	}
	return &extractCache{
		dir:      dir,
		maxBytes: maxBytes,
		perEntry: perEntry,
		gate:     gate,
		release:  release,
		byID:     make(map[string]*extractEntry),
		lru:      list.New(),
	}, nil
}

// readerAt returns a shared, seekable reader over the decompressed tar for the
// parent identified by sha, building it once across concurrent callers. The
// returned done func MUST be called when the caller finishes reading; it drops
// the reference so an evicted entry's disk can be reclaimed. fileType must be a
// compressed tar (IsCompressedTar). On a disabled cache, or when the archive is
// too large to cache, it returns errCacheDisabled / errCacheTooLarge and the
// caller streams directly.
func (c *extractCache) readerAt(ctx context.Context, sha string, src io.ReaderAt, size int64, fileType string) (cachedTar, error) {
	if c == nil {
		return cachedTar{}, errCacheDisabled
	}
	// A couple of attempts: acquire, else build once (shared across concurrent
	// callers via singleflight), then loop to take our own reference. The bound
	// guards against the rare race where a freshly built entry is evicted by a
	// concurrent build of a different parent before we acquire it — rather than
	// spin, we give up and stream directly.
	for range 3 {
		if e, ok := c.acquire(sha); ok {
			return cachedTar{r: e.file, size: e.size, done: func() { c.put(e) }}, nil
		}
		_, err, _ := c.group.Do(sha, func() (any, error) {
			if _, ok := c.peek(sha); ok {
				return struct{}{}, nil // another caller built it while we waited
			}
			return struct{}{}, c.build(ctx, sha, src, size, fileType)
		})
		if err != nil {
			return cachedTar{}, err
		}
	}
	return cachedTar{}, errCacheTooLarge
}

// acquire takes a reference to a live entry and marks it most-recently-used.
func (c *extractCache) acquire(sha string) (*extractEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[sha]
	if !ok || e.dead {
		return nil, false
	}
	e.refs++
	c.lru.MoveToFront(e.elem)
	return e, true
}

// peek reports whether a live entry exists without taking a reference.
func (c *extractCache) peek(sha string) (*extractEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[sha]
	return e, ok && !e.dead
}

// put drops a reference and closes+removes the file if the entry was evicted
// while it was held.
func (c *extractCache) put(e *extractEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.refs--
	if e.refs == 0 && e.dead {
		c.closeEntry(e)
	}
}

// build decompresses the parent tar to a temp file, unlinks it, and inserts the
// open handle. It holds an extraction slot for the decompression only, so the
// cost the slots bound is paid once per parent rather than once per member.
func (c *extractCache) build(ctx context.Context, sha string, src io.ReaderAt, size int64, fileType string) error {
	if c.gate != nil {
		if err := c.gate(ctx); err != nil {
			return err
		}
		defer c.release()
	}

	tmp, err := os.CreateTemp(c.dir, "extract-*.tar")
	if err != nil {
		return err
	}
	name := tmp.Name()
	n, derr := hopper.DecompressTar(src, size, fileType, c.perEntry, tmp)
	if cerr := tmp.Close(); cerr != nil && derr == nil {
		derr = cerr
	}
	if derr != nil {
		_ = os.Remove(name) //nolint:errcheck,gosec // best-effort cleanup of our own temp file
		if errors.Is(derr, hopper.ErrArchiveMemberTooLarge) {
			return errCacheTooLarge
		}
		return derr
	}

	// Reopen read-only and unlink: the open fd keeps the bytes alive (POSIX), so
	// disk is reclaimed when the last reader closes it and a crash leaks nothing.
	f, err := os.Open(name) //nolint:gosec // name is our own CreateTemp file under c.dir
	_ = os.Remove(name)     //nolint:errcheck,gosec // unlink our temp file; f retains the data
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	e := &extractEntry{sha: sha, file: f, size: n}
	e.elem = c.lru.PushFront(e)
	c.byID[sha] = e
	c.used += n
	c.evictLocked()
	return nil
}

// evictLocked walks the LRU from oldest to newest once, releasing unreferenced
// entries until the disk budget is met or the list is exhausted. Referenced
// entries are skipped, never reordered, so the budget is soft: a burst of
// distinct large archives may briefly exceed it rather than evict a file
// mid-read. Caller holds c.mu.
func (c *extractCache) evictLocked() {
	e := c.lru.Back()
	for c.used > c.maxBytes && e != nil {
		prev := e.Prev() // capture before closeEntry removes e from the list
		if entry, ok := e.Value.(*extractEntry); ok && entry.refs == 0 {
			c.closeEntry(entry)
		}
		e = prev
	}
}

// closeEntry detaches e from the cache and releases its file. If readers remain
// it is only marked dead; the final put closes it. Caller holds c.mu.
func (c *extractCache) closeEntry(e *extractEntry) {
	if _, ok := c.byID[e.sha]; ok {
		delete(c.byID, e.sha)
		c.lru.Remove(e.elem)
		c.used -= e.size
	}
	if e.refs > 0 {
		e.dead = true
		return
	}
	_ = e.file.Close() //nolint:errcheck // read-only handle; nothing to flush
}

// close releases every cached file. Used at shutdown; safe to call once.
func (c *extractCache) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.byID {
		e.dead = true
		if e.refs == 0 {
			_ = e.file.Close() //nolint:errcheck // best-effort shutdown
		}
	}
	c.byID = make(map[string]*extractEntry)
	c.lru.Init()
	c.used = 0
}
