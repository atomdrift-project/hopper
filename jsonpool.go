package hopper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// jsonBufPool recycles the read buffers used by DecodeJSONFrom.
var jsonBufPool sync.Pool

// JSONBufRetainCap is the largest buffer DecodeJSONFrom will return to its pool.
// Ordinary worker results sit far below this; an outlier is decoded normally and
// then dropped rather than pinning its capacity for the life of the process.
// Deliberately small relative to the API's body ceiling — the pool exists for
// the common case, not the extreme one.
const JSONBufRetainCap = 8 << 20 // 8 MiB

// DecodeJSONFrom reads one JSON document from r through a pooled buffer and
// unmarshals it into v. Prefer [DecodeJSONFromSize] when the size is knowable.
//
// This replaces json.NewDecoder(r).Decode(v) on hot paths. The streaming
// decoder looks like it avoids buffering the whole body, but for a single
// top-level value it does not: Decode reads until that entire value sits in the
// decoder's internal buffer, so peak memory is the same as reading the body.
// What differs is how it gets there — the internal buffer grows from nothing by
// repeated doubling, re-allocating and re-copying the document each time. At
// hopper's result-ingestion rate that regrowth alone accounted for over 5 GB of
// garbage, all of it avoidable.
//
// Reading into a pooled buffer keeps peak memory the same while making the
// steady state allocation-free.
//
// Safe to recycle: encoding/json copies into the destination — strings are
// freshly allocated and json.RawMessage does append((*m)[0:0], data...) — so
// nothing in v aliases the buffer once Unmarshal returns.
//
// Note this is stricter than Decoder.Decode in one respect: trailing bytes after
// the JSON value are rejected rather than ignored.
func DecodeJSONFrom(r io.Reader, v any) error {
	return DecodeJSONFromSize(r, 0, v)
}

// MaxJSONSizeHint bounds how much DecodeJSONFromSize will pre-allocate from a
// caller's hint. A hint is an estimate — on a compressed body it is a guess at
// the decompressed size — so it must never be trusted to size an allocation
// outright. Past this the buffer grows normally.
const MaxJSONSizeHint = 64 << 20 // 64 MiB

// DecodeJSONFromSize is DecodeJSONFrom with a caller's estimate of the decoded
// size, used to pre-allocate the read buffer.
//
// This matters more than the pooling does for large documents. A bytes.Buffer
// grown from nothing reaches size S by doubling, allocating and copying about
// 2S along the way; measured on hopper's result ingestion, buffers reached
// 256 MiB and the growth alone accounted for ~21 GB. Pooling cannot help there,
// because a buffer that large must be dropped rather than retained. A single
// correctly-sized allocation removes the whole doubling ladder.
//
// hint <= 0 means unknown, and the buffer grows as it would have.
func DecodeJSONFromSize(r io.Reader, hint int64, v any) error {
	buf, _ := jsonBufPool.Get().(*bytes.Buffer)
	if buf == nil {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	defer func() {
		if buf.Cap() <= JSONBufRetainCap {
			jsonBufPool.Put(buf)
		}
	}()

	if hint > 0 {
		if hint > MaxJSONSizeHint {
			hint = MaxJSONSizeHint
		}
		if grow := int(hint) - buf.Cap(); grow > 0 {
			buf.Grow(grow)
		}
	}
	if _, err := buf.ReadFrom(r); err != nil {
		return fmt.Errorf("read JSON: %w", err)
	}
	if err := json.Unmarshal(buf.Bytes(), v); err != nil {
		return err
	}
	return nil
}
