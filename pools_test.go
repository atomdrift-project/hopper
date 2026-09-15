package hopper

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
)

// TestBorrowZstdReaderReusesDecoder is the point of the pool: a released
// decoder must be usable again. Close() would leave it permanently broken, so
// this fails loudly if the release path ever regresses to Close.
func TestBorrowZstdReaderReusesDecoder(t *testing.T) {
	for i, want := range []string{"first payload", "second payload", "third payload"} {
		zr, release, err := BorrowZstdReader(bytes.NewReader(zstdBytes(t, []byte(want))))
		if err != nil {
			t.Fatalf("borrow %d: %v", i, err)
		}
		got, err := io.ReadAll(zr)
		release()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(got) != want {
			t.Errorf("round %d: got %q, want %q", i, got, want)
		}
	}
}

// TestBorrowZstdReaderConcurrent exercises the rule that a decoder decodes only
// one stream at a time: the pool must hand each goroutine its own.
func TestBorrowZstdReaderConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := strings.Repeat("payload", i+1)
			zr, release, err := BorrowZstdReader(bytes.NewReader(zstdBytes(t, []byte(want))))
			if err != nil {
				t.Errorf("borrow: %v", err)
				return
			}
			got, err := io.ReadAll(zr)
			release()
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if string(got) != want {
				t.Errorf("got %q, want %q", got, want)
			}
		}(i)
	}
	wg.Wait()
}

// TestDecodeJSONFromPoolReuseIsSafe guards the assumption the buffer pool rests
// on: a decoded value must not alias the pooled buffer, or a later decode would
// silently rewrite an earlier caller's data.
func TestDecodeJSONFromPoolReuseIsSafe(t *testing.T) {
	type doc struct {
		Name string          `json:"name"`
		Raw  json.RawMessage `json:"raw"`
	}
	var first doc
	if err := DecodeJSONFrom(strings.NewReader(`{"name":"alpha","raw":{"k":1}}`), &first); err != nil {
		t.Fatalf("first: %v", err)
	}
	name, raw := first.Name, string(first.Raw)

	for i := range 8 {
		var other doc
		body := `{"name":"` + strings.Repeat("z", 200+i) + `","raw":{"k":` + strings.Repeat("9", 50) + `}}`
		if err := DecodeJSONFrom(strings.NewReader(body), &other); err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
	}

	if first.Name != name || string(first.Raw) != raw {
		t.Errorf("first decode corrupted by reuse: name %q->%q raw %s->%s", name, first.Name, raw, first.Raw)
	}
}

// TestDecodeJSONFromRejectsBadJSON keeps the error path intact — handleResult
// distinguishes a truncated over-limit body from malformed input by this error.
func TestDecodeJSONFromRejectsBadJSON(t *testing.T) {
	var v map[string]any
	if err := DecodeJSONFrom(strings.NewReader(`{"truncated":`), &v); err == nil {
		t.Error("truncated document decoded without error")
	}
}

// TestDecodeJSONFromSizeHints checks that a hint only affects allocation, never
// the result — including hints that are wrong in either direction, since the
// zstd path's hint is an estimate that cannot be verified before reading.
func TestDecodeJSONFromSizeHints(t *testing.T) {
	const body = `{"name":"alpha","n":42}`
	for _, tc := range []struct {
		name string
		hint int64
	}{
		{"no hint", 0},
		{"negative", -1},
		{"exact", int64(len(body))},
		{"under-estimate", 4},
		{"over-estimate", 1 << 20},
		{"absurd, must be capped", 1 << 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v struct {
				Name string `json:"name"`
				N    int    `json:"n"`
			}
			if err := DecodeJSONFromSize(strings.NewReader(body), tc.hint, &v); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if v.Name != "alpha" || v.N != 42 {
				t.Errorf("got %+v, want {alpha 42}", v)
			}
		})
	}
}

// TestDecodeJSONFromSizeHintDoesNotOverAllocate pins the cap: a wild hint must
// not be turned into a wild allocation.
func TestDecodeJSONFromSizeHintDoesNotOverAllocate(t *testing.T) {
	var v map[string]any
	if err := DecodeJSONFromSize(strings.NewReader(`{"a":1}`), 1<<40, &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The buffer that just served this decode is back in the pool; borrow it
	// and confirm the cap bounded its capacity.
	buf, _ := jsonBufPool.Get().(*bytes.Buffer)
	if buf != nil {
		defer jsonBufPool.Put(buf)
		if buf.Cap() > MaxJSONSizeHint+(1<<20) {
			t.Errorf("buffer capacity %d exceeds cap %d", buf.Cap(), MaxJSONSizeHint)
		}
	}
}
