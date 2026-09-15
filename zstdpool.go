package hopper

import (
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// zstdDecoderPool recycles zstd stream decoders. It has no New func: building a
// decoder can fail, and a sync.Pool's New cannot report that, so BorrowZstdReader
// constructs on miss and handles the error there.
var zstdDecoderPool sync.Pool

// BorrowZstdReader returns a zstd stream decoder reading from r, plus a release
// func the caller must invoke when done.
//
// Constructing a decoder per stream is what this avoids: each zstd.NewReader
// allocates fresh window/history buffers, and at hopper's rate of compressed
// worker results that made zstd history allocation the single largest source of
// garbage in the process — more than all JSON handling combined. The library
// documents Reset as the remedy ("will considerably reduce the allocations
// normally caused by NewReader"), so decoders are kept and re-pointed instead.
//
// The release func calls Reset(nil), NOT Close: Close marks a decoder
// permanently unusable (every later Reset returns ErrDecoderClosed), which would
// poison the pool. Reset(nil) drops the decoder's reference to r — so the
// underlying stream can be collected — while leaving the decoder reusable.
//
// The decoder is exclusively owned between borrow and release, which satisfies
// the library's rule that only one stream may be decoded per decoder at a time.
// Callers must not use the reader after releasing it.
func BorrowZstdReader(r io.Reader) (io.Reader, func(), error) {
	dec, _ := zstdDecoderPool.Get().(*zstd.Decoder)
	if dec == nil {
		var err error
		dec, err = zstd.NewReader(nil, zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, nil, fmt.Errorf("zstd: %w", err)
		}
	}
	if err := dec.Reset(r); err != nil {
		// A decoder that will not reset is dropped rather than returned to the
		// pool, so one bad stream cannot strand a broken decoder there.
		return nil, nil, fmt.Errorf("zstd: %w", err)
	}
	return dec, func() {
		if err := dec.Reset(nil); err != nil {
			return // unusable; drop it instead of pooling it
		}
		zstdDecoderPool.Put(dec)
	}, nil
}
