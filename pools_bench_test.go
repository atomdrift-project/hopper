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
