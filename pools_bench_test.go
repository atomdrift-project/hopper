package hopper

import (
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func benchPayload(b *testing.B, n int) []byte {
	b.Helper()
	raw := bytes.Repeat([]byte(`{"sha256":"deadbeef","traits":["a","b","c"]},`), n)
	var out bytes.Buffer
	w, err := zstd.NewWriter(&out)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	return out.Bytes()
}

// BenchmarkZstdNewReaderPerStream is the shape this code used before: a decoder
// constructed per stream, each allocating fresh window/history buffers.
func BenchmarkZstdNewReaderPerStream(b *testing.B) {
	payload := benchPayload(b, 2000)
	b.ReportAllocs()
	for b.Loop() {
		zr, err := zstd.NewReader(bytes.NewReader(payload),
			zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, zr); err != nil {
			b.Fatal(err)
		}
		zr.Close()
	}
}

// BenchmarkZstdBorrowPooled is the replacement: decoders are kept and re-pointed.
func BenchmarkZstdBorrowPooled(b *testing.B) {
	payload := benchPayload(b, 2000)
	b.ReportAllocs()
	for b.Loop() {
		zr, release, err := BorrowZstdReader(bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, zr); err != nil {
			b.Fatal(err)
		}
		release()
	}
}

// benchJSONDoc builds a result-shaped document of roughly n bytes.
func benchJSONDoc(n int) []byte {
	entry := `{"sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","path":"usr/lib/libc.so","depth":1,"traits":["elf"]},`
	var b []byte
	b = append(b, `{"worker":"w","sha256":"deadbeef","raw":{"files":[`...)
	for len(b) < n {
		b = append(b, entry...)
	}
	b = b[:len(b)-1]
	return append(b, `]}}`...)
}

// BenchmarkDecodeJSONNoHint is the un-hinted path: the buffer doubles up to size.
func BenchmarkDecodeJSONNoHint(b *testing.B) {
	doc := benchJSONDoc(32 << 20)
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for b.Loop() {
		var v map[string]any
		if err := DecodeJSONFromSize(bytes.NewReader(doc), 0, &v); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecodeJSONWithHint pre-sizes from a known Content-Length.
func BenchmarkDecodeJSONWithHint(b *testing.B) {
	doc := benchJSONDoc(32 << 20)
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	for b.Loop() {
		var v map[string]any
		if err := DecodeJSONFromSize(bytes.NewReader(doc), int64(len(doc)), &v); err != nil {
			b.Fatal(err)
		}
	}
}
