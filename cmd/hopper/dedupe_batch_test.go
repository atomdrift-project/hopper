package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
)

func TestDedupeLocationBatchBoundsConcurrency(t *testing.T) {
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			shas := make([]string, 20)
			for i := range shas {
				shas[i] = fmt.Sprint(i)
			}
			entered := make(chan struct{}, len(shas))
			release := make(chan struct{})
			var active, peak, calls atomic.Int32
			type outcome struct {
				result hopper.DedupeResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := dedupeLocationBatch(ctx, shas, workers, func(ctx context.Context, _ string) (hopper.DedupeResult, error) {
					calls.Add(1)
					current := active.Add(1)
					defer active.Add(-1)
					for {
						old := peak.Load()
						if current <= old || peak.CompareAndSwap(old, current) {
							break
						}
					}
					entered <- struct{}{}
					select {
					case <-release:
					case <-ctx.Done():
						return hopper.DedupeResult{}, ctx.Err()
					}
					return hopper.DedupeResult{Linked: 1, Removed: 1, Obsolete: 1, Unresolved: 1, Skipped: 1, BytesSaved: 10}, nil
				})
				done <- outcome{result, err}
			}()
			for range workers {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if got := active.Load(); got != int32(workers) {
				t.Fatalf("active=%d want=%d", got, workers)
			}
			close(release)
			got := <-done
			want := hopper.DedupeResult{Linked: 20, Removed: 20, Obsolete: 20, Unresolved: 20, Skipped: 20, BytesSaved: 200}
			if got.err != nil || got.result != want || calls.Load() != 20 || peak.Load() > int32(workers) {
				t.Fatalf("result=%+v err=%v calls=%d peak=%d", got.result, got.err, calls.Load(), peak.Load())
			}
		})
	}
}

func TestDedupeLocationBatchFailureDoesNotCommitProgress(t *testing.T) {
	failure := errors.New("failed sample")
	result, err := dedupeLocationBatch(t.Context(), []string{"bad", "other", "third"}, 2, func(ctx context.Context, sha string) (hopper.DedupeResult, error) {
		if sha == "bad" {
			return hopper.DedupeResult{}, failure
		}
		<-ctx.Done()
		return hopper.DedupeResult{}, ctx.Err()
	})
	if !errors.Is(err, failure) || result != (hopper.DedupeResult{}) {
		t.Fatalf("partial result exposed: %+v %v", result, err)
	}
	if _, err := dedupeLocationBatch(t.Context(), nil, 0, nil); err == nil {
		t.Fatal("accepted zero workers")
	}
}
