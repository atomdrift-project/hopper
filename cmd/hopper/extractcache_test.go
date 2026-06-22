package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"codeberg.org/atomdrift/hopper"
	"github.com/ulikunitz/xz"
)

// xzTarBytes builds an xz-wrapped tar holding the given members.
func xzTarBytes(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	var out bytes.Buffer
	xw, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := xw.Write(raw.Bytes()); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := xw.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return out.Bytes()
}

func TestExtractCacheDisabled(t *testing.T) {
	// A zero budget yields a nil cache; readerAt on it reports disabled so the
	// caller streams directly.
	c, err := newExtractCache(t.TempDir(), 0, 1<<20, nil, nil)
	if err != nil {
		t.Fatalf("newExtractCache: %v", err)
	}
	if c != nil {
		t.Fatalf("expected nil cache for zero budget, got %v", c)
	}
	if _, rerr := c.readerAt(context.Background(), "sha", nil, 0, "tar.xz"); !errors.Is(rerr, errCacheDisabled) {
		t.Fatalf("readerAt on nil cache = %v, want errCacheDisabled", rerr)
	}
}

func TestExtractCacheServesAndReusesBuild(t *testing.T) {
	archive := xzTarBytes(t, map[string]string{"dir/a.txt": "alpha", "dir/b.txt": "bravo"})
	src := bytes.NewReader(archive)

	// gate counts builds: it is called once per decompression, never on a hit.
	var builds atomic.Int32
	gate := func(context.Context) error { builds.Add(1); return nil }

	c, err := newExtractCache(t.TempDir(), 1<<30, 1<<30, gate, func() {})
	if err != nil {
		t.Fatalf("newExtractCache: %v", err)
	}
	t.Cleanup(c.close)

	read := func(member string) string {
		t.Helper()
		ct, rerr := c.readerAt(context.Background(), "parent", src, int64(len(archive)), "tar.xz")
		if rerr != nil {
			t.Fatalf("readerAt: %v", rerr)
		}
		defer ct.done()
		got, eerr := hopperExtract(ct.r, ct.size, member)
		if eerr != nil {
			t.Fatalf("extract %q: %v", member, eerr)
		}
		return got
	}

	if got := read("a.txt"); got != "alpha" {
		t.Errorf("a.txt = %q, want alpha", got)
	}
	if got := read("b.txt"); got != "bravo" {
		t.Errorf("b.txt = %q, want bravo", got)
	}
	if n := builds.Load(); n != 1 {
		t.Fatalf("decompressed %d times, want 1 (cache should reuse the build)", n)
	}
}

func TestExtractCacheSingleflightOneBuild(t *testing.T) {
	archive := xzTarBytes(t, map[string]string{"x.txt": "data"})
	src := bytes.NewReader(archive)

	// The gate blocks until released, holding the first builder so a burst of
	// concurrent callers must coalesce onto the single in-flight build.
	var builds atomic.Int32
	release := make(chan struct{})
	gate := func(context.Context) error {
		builds.Add(1)
		<-release
		return nil
	}
	c, err := newExtractCache(t.TempDir(), 1<<30, 1<<30, gate, func() {})
	if err != nil {
		t.Fatalf("newExtractCache: %v", err)
	}
	t.Cleanup(c.close)

	const callers = 8
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			ct, rerr := c.readerAt(context.Background(), "p", src, int64(len(archive)), "tar.xz")
			if rerr != nil {
				t.Errorf("readerAt: %v", rerr)
				return
			}
			defer ct.done()
			if got, eerr := hopperExtract(ct.r, ct.size, "x.txt"); eerr != nil || got != "data" {
				t.Errorf("extract = %q, %v; want data", got, eerr)
			}
		})
	}
	close(release) // let the single build finish; the rest ride its result
	wg.Wait()

	if n := builds.Load(); n != 1 {
		t.Fatalf("gate entered %d times, want 1 (singleflight should collapse the burst)", n)
	}
}

func TestExtractCacheEvictsToBudget(t *testing.T) {
	// Two distinct parents, a budget that fits only one decompressed tar: the
	// first must be evicted (its file removed) when the second is built.
	a := xzTarBytes(t, map[string]string{"a.txt": "AAAA"})
	b := xzTarBytes(t, map[string]string{"b.txt": "BBBB"})

	// Size the budget off the actual decompressed tar: big enough for one, too
	// small for two. (perEntry must stay ≥ one tar, so don't clamp it below that.)
	one := decompressedSize(t, a)
	budget := one + one/2 // holds exactly one

	c, err := newExtractCache(t.TempDir(), budget, budget, func(context.Context) error { return nil }, func() {})
	if err != nil {
		t.Fatalf("newExtractCache: %v", err)
	}
	t.Cleanup(c.close)

	ctA, err := c.readerAt(context.Background(), "A", bytes.NewReader(a), int64(len(a)), "tar.xz")
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	ctA.done() // release the reference so A is evictable

	ctB, err := c.readerAt(context.Background(), "B", bytes.NewReader(b), int64(len(b)), "tar.xz")
	if err != nil {
		t.Fatalf("build B: %v", err)
	}
	ctB.done()

	c.mu.Lock()
	_, hasA := c.byID["A"]
	_, hasB := c.byID["B"]
	used := c.used
	c.mu.Unlock()
	if hasA {
		t.Error("parent A should have been evicted to meet the budget")
	}
	if !hasB {
		t.Error("parent B should be resident")
	}
	if used > budget {
		t.Errorf("used = %d, over budget %d", used, budget)
	}
}

// decompressedSize reports how many bytes an xz-tar expands to.
func decompressedSize(t *testing.T, archive []byte) int64 {
	t.Helper()
	n, err := hopper.DecompressTar(bytes.NewReader(archive), int64(len(archive)), "tar.xz", -1, io.Discard)
	if err != nil {
		t.Fatalf("decompressedSize: %v", err)
	}
	return n
}

func TestExtractCacheTooLargeFallsBack(t *testing.T) {
	archive := xzTarBytes(t, map[string]string{"big.txt": "0123456789ABCDEF"})
	// perEntry below the decompressed size → errCacheTooLarge, signalling the
	// caller to stream directly.
	c, err := newExtractCache(t.TempDir(), 1<<30, 8, func(context.Context) error { return nil }, func() {})
	if err != nil {
		t.Fatalf("newExtractCache: %v", err)
	}
	t.Cleanup(c.close)
	if _, rerr := c.readerAt(context.Background(), "p", bytes.NewReader(archive), int64(len(archive)), "tar.xz"); !errors.Is(rerr, errCacheTooLarge) {
		t.Fatalf("readerAt = %v, want errCacheTooLarge", rerr)
	}
}

func TestExtractCacheGateRejection(t *testing.T) {
	// A gate that refuses (slots exhausted / ctx done) surfaces its error so the
	// handler maps it to 503 busy.
	sentinel := errors.New("no slot")
	c, err := newExtractCache(t.TempDir(), 1<<30, 1<<30, func(context.Context) error { return sentinel }, func() {})
	if err != nil {
		t.Fatalf("newExtractCache: %v", err)
	}
	t.Cleanup(c.close)
	archive := xzTarBytes(t, map[string]string{"x": "y"})
	if _, rerr := c.readerAt(context.Background(), "p", bytes.NewReader(archive), int64(len(archive)), "tar.xz"); !errors.Is(rerr, sentinel) {
		t.Fatalf("readerAt = %v, want gate sentinel", rerr)
	}
}

// hopperExtract pulls one member out of an already-decompressed tar via the same
// entry point the handler uses, so tests exercise the real extraction path.
func hopperExtract(rdr io.ReaderAt, size int64, member string) (string, error) {
	var out bytes.Buffer
	if err := hopper.StreamArchiveMember(rdr, size, "tar", member, 1<<20, func(int64) {}, &out); err != nil {
		return "", err
	}
	return out.String(), nil
}
