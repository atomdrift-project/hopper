package hopper

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper/internal/storageproto"
)

// BenchmarkStorageWriter compares the observation layer only. Both sides use
// the same COPY input, identity-resolution work, foreign keys, and seven location
// access paths. Legacy executes Hopper's real locationsFromStagingPG; neither
// side includes samples' analysis payloads, labels, queues, or their indexes.
//
// HOPPER_STORAGE_DSN must name local hopper_schema_prototype. HOPPER_STORAGE_CSV
// is a successful cohort export from scripts/storage-prototype-fetch.sql.
// HOPPER_STORAGE_PRELOAD_BATCHES optionally seeds unrelated batches before timing.
// Run alone on the disposable cluster: WAL LSN deltas are server-wide.
func BenchmarkStorageWriter(b *testing.B) {
	dsn := os.Getenv("HOPPER_STORAGE_DSN")
	if dsn == "" {
		b.Skip("set HOPPER_STORAGE_DSN")
	}
	input := readStorageObservations(b)
	for _, scenario := range []string{"new", "shared_paths", "repeat", "relocated_archive", "parallel_repeat"} {
		for _, layout := range []string{"legacy", "compact"} {
			b.Run(scenario+"/"+layout, func(b *testing.B) {
				runStorageBenchmark(b, dsn, input, scenario, layout)
			})
		}
	}
}

func readStorageObservations(b *testing.B) []storageproto.Observation {
	b.Helper()
	path := os.Getenv("HOPPER_STORAGE_CSV")
	if path == "" {
		b.Skip("set HOPPER_STORAGE_CSV to a complete cohort export")
	}
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // read-only fixture
	r := csv.NewReader(f)
	if _, err = r.Read(); err != nil {
		b.Fatal(err)
	}
	var out []storageproto.Observation
	for len(out) < 1000 {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			b.Fatal(err)
		}
		o := storageproto.Observation{SHA256: row[4], Path: row[5], ParentSHA256: row[6], Rel: row[7], Filename: row[8], Source: row[9], Feed: row[10], Ecosystem: row[11]}
		if row[12] != "" {
			var stamp time.Time
			for _, format := range []string{"2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano} {
				stamp, err = time.Parse(format, row[12])
				if err == nil {
					break
				}
			}
			if err != nil {
				b.Fatal(err)
			}
			o.Mtime = &stamp
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		b.Fatal("empty cohort")
	}
	return out
}

func storageBatch(input []storageproto.Observation, scenario string, iteration int) []storageproto.Observation {
	out := slices.Clone(input)
	if scenario == "repeat" || scenario == "parallel_repeat" {
		return out
	}
	salt := strconv.Itoa(iteration)
	hash := func(s string) string { h := sha256.Sum256([]byte(s + "/" + salt)); return hex.EncodeToString(h[:]) }
	for i := range out {
		o := &out[i]
		o.Path = "bench/" + salt + "/" + o.Path
		if scenario != "relocated_archive" {
			o.SHA256 = hash(o.SHA256)
			if o.ParentSHA256 != "" {
				o.ParentSHA256 = hash(o.ParentSHA256)
			}
		}
		if scenario == "new" {
			if n := strings.LastIndex(o.Path, "!!"); n >= 0 {
				old := o.Path[n+2:]
				o.Path = o.Path[:n+2] + salt + "/" + old
				if o.Filename == old {
					o.Filename = salt + "/" + old
				}
			}
		}
	}
	return out
}

func runStorageBenchmark(b *testing.B, dsn string, input []storageproto.Observation, scenario, layout string) {
	b.Helper()
	ctx := context.Background()
	s, err := storageproto.Open(ctx, dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := s.Close(ctx); err != nil {
			b.Error(err)
		}
	}()
	write := s.Write
	if layout == "legacy" {
		write = func(ctx context.Context, rows []storageproto.Observation) (int64, error) {
			return s.WriteLegacy(ctx, rows, locationsFromStagingPG)
		}
	}
	tables := []string{"identities", "relative_paths", "parent_locations", "locations"}
	locationTable := "locations"
	if layout == "legacy" {
		tables = []string{"samples", "sample_locations"}
		locationTable = "sample_locations"
	}
	if value := os.Getenv("HOPPER_STORAGE_PRELOAD_BATCHES"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			b.Fatal("HOPPER_STORAGE_PRELOAD_BATCHES must be a nonnegative integer")
		}
		for i := range n {
			if _, err := write(ctx, storageBatch(input, "new", -i-1)); err != nil {
				b.Fatal(err)
			}
		}
		// Existing tables should have planner statistics before measurement;
		// do not let autovacuum's timing favor one layout over the other.
		for _, table := range tables {
			if _, err := s.Pool.Exec(ctx, "ANALYZE "+table); err != nil {
				b.Fatal(err)
			}
		}
	}
	if scenario != "new" {
		if _, err = write(ctx, input); err != nil {
			b.Fatal(err)
		}
	}
	batches := make([][]storageproto.Observation, b.N)
	for i := range batches {
		batches[i] = storageBatch(input, scenario, i)
	}
	if _, err = s.Pool.Exec(ctx, "CHECKPOINT"); err != nil {
		b.Fatal(err)
	}
	var startLSN string
	if err = s.Pool.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&startLSN); err != nil {
		b.Fatal(err)
	}
	stopMonitor := monitorStorageLocks(b, s)
	latencies := make([]int64, b.N)
	errorsOut := make(chan error, b.N)
	b.ResetTimer()
	if scenario == "parallel_repeat" {
		jobs := make(chan int, b.N)
		for i := range batches {
			jobs <- i
		}
		close(jobs)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				for i := range jobs {
					started := time.Now()
					_, err := write(ctx, batches[i])
					latencies[i] = time.Since(started).Nanoseconds()
					if err != nil {
						errorsOut <- err
					}
				}
			})
		}
		wg.Wait()
	} else {
		for i := range batches {
			started := time.Now()
			_, err := write(ctx, batches[i])
			latencies[i] = time.Since(started).Nanoseconds()
			if err != nil {
				errorsOut <- err
			}
		}
	}
	b.StopTimer()
	lockSamples, polls := stopMonitor()
	close(errorsOut)
	for err := range errorsOut {
		b.Fatal(err)
	}
	var wal float64
	if err = s.Pool.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::float8`, startLSN).Scan(&wal); err != nil {
		b.Fatal(err)
	}
	slices.Sort(latencies)
	offered := float64(b.N * len(input))
	b.ReportMetric(offered/b.Elapsed().Seconds(), "obs/s")
	b.ReportMetric(wal/offered, "WAL-B/obs")
	b.ReportMetric(float64(latencies[len(latencies)/2])/1e6, "p50-ms/batch")
	b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100])/1e6, "p95-ms/batch")
	b.ReportMetric(float64(lockSamples), "lock-wait-samples")
	b.ReportMetric(float64(polls), "lock-polls")
	var bytes, n int64
	if err = s.Pool.QueryRow(ctx, `SELECT sum(pg_total_relation_size(oid)) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY($1)`, tables).Scan(&bytes); err != nil {
		b.Fatal(err)
	}
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM "+locationTable).Scan(&n); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(bytes)/float64(n), "stored-B/location")
}

// This is a 10ms sample of Lock waits, not exact wait duration. Acquiring its
// connection before timing avoids competing with a writer for a pool slot.
func monitorStorageLocks(b *testing.B, s *storageproto.Store) func() (int64, int64) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		b.Fatal(err)
	}
	var waits, polls atomic.Int64
	done := make(chan struct{})
	app := s.Pool.Config().ConnConfig.RuntimeParams["application_name"]
	go func() {
		defer close(done)
		defer conn.Release()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var n int64
				if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'`, app).Scan(&n); err == nil {
					waits.Add(n)
					polls.Add(1)
				}
			}
		}
	}()
	return func() (int64, int64) { cancel(); <-done; return waits.Load(), polls.Load() }
}
