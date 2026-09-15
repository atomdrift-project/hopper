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
// unmarshals it into v.
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

	if _, err := buf.ReadFrom(r); err != nil {
		return fmt.Errorf("read JSON: %w", err)
	}
	if err := json.Unmarshal(buf.Bytes(), v); err != nil {
		return err
	}
	return nil
}
