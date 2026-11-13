package storageproto

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("HOPPER_STORAGE_DSN")
	if dsn == "" {
		t.Skip("set HOPPER_STORAGE_DSN to local hopper_schema_prototype")
	}
	s, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return s
}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func version(t *testing.T, s *Store, table string) string {
	t.Helper()
	var got string
	if err := s.Pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(id::text||':'||xmin::text||':'||ctid::text,',' ORDER BY id),'') FROM `+table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.Pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRefuseNonlocalDatabase(t *testing.T) {
	for _, dsn := range []string{"postgres://t@minas-tirith/hopper_schema_prototype", "postgres://t@/hopper?host=/tmp"} {
		if s, err := Open(t.Context(), dsn); err == nil {
			if err := s.Close(t.Context()); err != nil {
				t.Error(err)
			}
			t.Fatalf("accepted %s", dsn)
		}
	}
}

func TestRoundTripAndRepeatedObservation(t *testing.T) {
	s := testStore(t)
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	observations := []Observation{
		{SHA256: digest("root"), Path: "pool/root", Filename: "display", Source: "collector"},
		{SHA256: digest("child"), ParentSHA256: digest("root"), Path: "pool/root!!embedded:pe@0x12000", Filename: "embedded:pe@0x12000", Mtime: &stamp},
		{SHA256: digest("nested"), ParentSHA256: digest("child"), Path: "pool/root!!embedded:pe@0x12000!!inner", Filename: "inner", Rel: "unpacked"},
		{SHA256: digest("decoded"), ParentSHA256: digest("root"), Path: "pool/root##base64+gzip@1234", Filename: "", Rel: "unpacked"},
		{SHA256: digest("unknown"), Path: "absent.zip!!file", Filename: "file"},
		{SHA256: digest("child"), ParentSHA256: digest("other"), Path: "other.zip!!embedded:pe@0x12000", Filename: "embedded:pe@0x12000", Feed: "npm", Ecosystem: "javascript"},
	}
	if n, err := s.Write(t.Context(), observations); err != nil || n != int64(len(observations)) {
		t.Fatalf("insert: %d %v", n, err)
	}
	for _, o := range observations {
		var got Observation
		err := s.Pool.QueryRow(t.Context(), `SELECT sha256,parent_sha256,path,filename,rel,source,feed,ecosystem,mtime FROM reconstructed WHERE sha256=$1 AND path=$2`, o.SHA256, o.Path).
			Scan(&got.SHA256, &got.ParentSHA256, &got.Path, &got.Filename, &got.Rel, &got.Source, &got.Feed, &got.Ecosystem, &got.Mtime)
		if err != nil {
			t.Fatal(err)
		}
		// PostgreSQL timestamps carry the local driver's timezone; compare instants.
		if o.Mtime != nil && (got.Mtime == nil || !got.Mtime.Equal(*o.Mtime)) {
			t.Fatalf("mtime: %+v", got)
		}
		got.Mtime = o.Mtime
		if !reflect.DeepEqual(o, got) {
			t.Fatalf("round trip: got %+v want %+v", got, o)
		}
	}
	if n := count(t, s, "relative_paths"); n != 2 {
		t.Fatalf("relative strings stored %d times, want 2", n)
	}
	before := map[string]string{}
	for _, table := range []string{"identities", "relative_paths", "parent_locations", "locations"} {
		before[table] = version(t, s, table)
	}
	for range 2 {
		if n, err := s.Write(t.Context(), append(observations, observations...)); err != nil || n != 0 {
			t.Fatalf("repeat: %d %v", n, err)
		}
	}
	for table, want := range before {
		if got := version(t, s, table); got != want {
			t.Fatalf("%s changed on repeat", table)
		}
	}
}

func TestMetadataAndParentIdentity(t *testing.T) {
	s := testStore(t)
	o := Observation{SHA256: digest("a"), ParentSHA256: digest("parent"), Path: "p.zip!!file", Filename: "file"}
	if _, err := s.Write(t.Context(), []Observation{o}); err != nil {
		t.Fatal(err)
	}
	original := o.ParentSHA256
	// Same full path, different claimed parent: retain the original association,
	// matching Hopper, rather than creating a second location under another ID.
	o.ParentSHA256 = digest("different parent")
	o.Source, o.Feed, o.Ecosystem, o.Rel = "first", "feed", "eco", "unpacked"
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	o.Mtime = &stamp
	if n, err := s.Write(t.Context(), []Observation{o}); err != nil || n != 1 {
		t.Fatalf("enrich: %d %v", n, err)
	}
	if n := count(t, s, "locations"); n != 1 {
		t.Fatalf("duplicate location: %d", n)
	}
	var parent, source, feed, eco, rel string
	var mtime time.Time
	if err := s.Pool.QueryRow(t.Context(), `SELECT parent_sha256,source,feed,ecosystem,rel,mtime FROM reconstructed`).Scan(&parent, &source, &feed, &eco, &rel, &mtime); err != nil {
		t.Fatal(err)
	}
	if parent != original || source != "first" || feed != "feed" || eco != "eco" || rel != "unpacked" || !mtime.Equal(stamp) {
		t.Fatalf("metadata: %s %s %s %s %s %v", parent, source, feed, eco, rel, mtime)
	}
	before := version(t, s, "locations")
	o.Source, o.Feed, o.Ecosystem, o.Rel, o.Mtime = "later", "", "", "", nil
	if n, err := s.Write(t.Context(), []Observation{o}); err != nil || n != 0 {
		t.Fatalf("preserve metadata: %d %v", n, err)
	}
	if got := version(t, s, "locations"); got != before {
		t.Fatal("unchanged metadata rewritten")
	}
}

func forceCollisions(t *testing.T, s *Store) {
	t.Helper()
	// Install before inserting any rows, so the expression index remains valid.
	if _, err := s.Pool.Exec(t.Context(), `CREATE OR REPLACE FUNCTION path_key(path text) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE RETURN decode(repeat('00',32),'hex')`); err != nil {
		t.Fatal(err)
	}
}

func TestCollisionRollsBackWholeBatch(t *testing.T) {
	for _, kind := range []string{"relative", "parent", "full path"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			forceCollisions(t, s)
			first := Observation{SHA256: digest("child"), ParentSHA256: digest("parent"), Path: "p!!a", Filename: "a"}
			if kind == "full path" {
				first.ParentSHA256 = ""
				first.Path = "a"
			}
			if _, err := s.Write(t.Context(), []Observation{first}); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			for _, table := range []string{"identities", "relative_paths", "parent_locations", "locations"} {
				before[table] = version(t, s, table)
			}
			second := first
			switch kind {
			case "relative":
				second.Path = "p!!b"
			case "parent":
				second.Path = "q!!a"
			case "full path":
				second.Path = "b"
			}
			// A distinct sample earlier in the same batch must be rolled back too.
			extra := Observation{SHA256: digest("extra"), Path: "extra"}
			if _, err := s.Write(t.Context(), []Observation{extra, second}); !errors.Is(err, ErrCollision) {
				t.Fatalf("collision: %v", err)
			}
			for table, want := range before {
				if got := version(t, s, table); got != want {
					t.Fatalf("%s changed after rejected batch", table)
				}
			}
		})
	}
}

func TestDuplicateObservationWithMetadataChange(t *testing.T) {
	for _, changedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_first=%v", changedFirst), func(t *testing.T) {
			s := testStore(t)
			unchanged := Observation{SHA256: digest("child"), Path: "p!!a"}
			if _, err := s.Write(t.Context(), []Observation{unchanged}); err != nil {
				t.Fatal(err)
			}
			changed := unchanged
			changed.Feed = "npm"
			batch := []Observation{unchanged, changed}
			if changedFirst {
				batch[0], batch[1] = batch[1], batch[0]
			}
			if n, err := s.Write(t.Context(), batch); err != nil || n != 1 {
				t.Fatalf("duplicate enrichment: %d %v", n, err)
			}
			var feed string
			if err := s.Pool.QueryRow(t.Context(), `SELECT feed FROM locations`).Scan(&feed); err != nil || feed != changed.Feed {
				t.Fatalf("duplicate lost metadata: %q %v", feed, err)
			}
		})
	}
}

func TestCollisionsWithinBatch(t *testing.T) {
	for _, kind := range []string{"relative", "parent", "full path"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			forceCollisions(t, s)
			first := Observation{SHA256: digest("child"), ParentSHA256: digest("parent"), Path: "p!!a"}
			second := first
			switch kind {
			case "relative":
				second.Path = "p!!b"
			case "parent":
				second.Path = "q!!a"
			case "full path":
				first.ParentSHA256, second.ParentSHA256 = "", ""
				first.Path, second.Path = "a", "b"
			}
			if _, err := s.Write(t.Context(), []Observation{first, second}); !errors.Is(err, ErrCollision) {
				t.Fatalf("collision within batch: %v", err)
			}
			for _, table := range []string{"identities", "relative_paths", "parent_locations", "locations"} {
				if count(t, s, table) != 0 {
					t.Fatalf("%s retained part of a rejected batch", table)
				}
			}
		})
	}
}

func TestDuplicateLocationDoesNotHideCollision(t *testing.T) {
	s := testStore(t)
	forceCollisions(t, s)
	seed := Observation{SHA256: digest("seed"), ParentSHA256: digest("q"), Path: "q!!a"}
	if _, err := s.Write(t.Context(), []Observation{seed}); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, table := range []string{"identities", "relative_paths", "parent_locations", "locations"} {
		before[table] = version(t, s, table)
	}
	first := Observation{SHA256: digest("child"), ParentSHA256: digest("p"), Path: "p!!a"}
	second := first
	second.ParentSHA256 = seed.ParentSHA256
	// Both rows have the same sample and full path. The second parent's path
	// collides with q!!a's parent placement and must be checked before deduping.
	if _, err := s.Write(t.Context(), []Observation{first, second}); !errors.Is(err, ErrCollision) {
		t.Fatalf("duplicate hid parent collision: %v", err)
	}
	for table, want := range before {
		if version(t, s, table) != want {
			t.Fatalf("%s changed after rejected duplicates", table)
		}
	}
}

func TestConcurrentWriters(t *testing.T) {
	for _, kind := range []string{"none", "relative", "full path"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			collision := kind != "none"
			if collision {
				forceCollisions(t, s)
			}
			// Preexisting identities keep the race from being serialized by their
			// unique index before the concurrent dictionary/location inserts.
			if _, err := s.Pool.Exec(t.Context(), `INSERT INTO identities(sha256) VALUES(decode($1,'hex')),(decode($2,'hex'))`, digest("child"), digest("parent")); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			results := make(chan error, 6)
			var wg sync.WaitGroup
			for i := range 6 {
				wg.Go(func() {
					<-start
					o := Observation{SHA256: digest("child"), ParentSHA256: digest("parent"), Path: "p!!file", Filename: "file"}
					if collision {
						o.Path = fmt.Sprintf("p!!file-%d", i)
					}
					if kind == "full path" {
						o.ParentSHA256 = ""
					}
					_, err := s.Write(t.Context(), []Observation{o})
					results <- err
				})
			}
			close(start)
			wg.Wait()
			close(results)
			success, collisions := 0, 0
			for err := range results {
				switch {
				case err == nil:
					success++
				case errors.Is(err, ErrCollision):
					collisions++
				default:
					t.Fatal(err)
				}
			}
			if collision && (success != 1 || collisions != 5) {
				t.Fatalf("success=%d collisions=%d", success, collisions)
			}
			if !collision && success != 6 {
				t.Fatalf("success=%d", success)
			}
			dictionaryRows := 1
			if kind == "full path" {
				dictionaryRows = 0
			}
			if count(t, s, "locations") != 1 || count(t, s, "relative_paths") != dictionaryRows || count(t, s, "parent_locations") != dictionaryRows || count(t, s, "identities") != 2 {
				t.Fatal("concurrent writers duplicated identities or locations")
			}
		})
	}
}

func TestMixedBatch(t *testing.T) {
	s := testStore(t)
	unchanged := Observation{SHA256: digest("unchanged"), ParentSHA256: digest("parent"), Path: "p!!same"}
	changed := Observation{SHA256: digest("changed"), ParentSHA256: digest("parent"), Path: "p!!changed"}
	if _, err := s.Write(t.Context(), []Observation{unchanged, changed}); err != nil {
		t.Fatal(err)
	}
	// Lock the unchanged location to prove mixed batches also skip its upsert.
	tx, err := s.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck // test cleanup
	if _, err := tx.Exec(t.Context(), `SELECT id FROM locations WHERE full_path_key=path_key($1) FOR UPDATE`, unchanged.Path); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := s.Pool.QueryRow(t.Context(), `SELECT xmin::text||ctid::text FROM locations WHERE full_path_key=path_key($1)`, unchanged.Path).Scan(&before); err != nil {
		t.Fatal(err)
	}
	changed.Feed = "npm"
	added := Observation{SHA256: digest("added"), ParentSHA256: digest("parent"), Path: "p!!added"}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	batch := []Observation{unchanged, changed, added}
	if n, err := s.Write(ctx, batch); err != nil || n != 2 {
		t.Fatalf("mixed batch: %d %v", n, err)
	}
	var after, feed string
	if err := s.Pool.QueryRow(t.Context(), `SELECT xmin::text||ctid::text FROM locations WHERE full_path_key=path_key($1)`, unchanged.Path).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after || count(t, s, "locations") != 3 {
		t.Fatal("unchanged row rewritten or new row missing")
	}
	if err := s.Pool.QueryRow(t.Context(), `SELECT feed FROM reconstructed WHERE path=$1`, changed.Path).Scan(&feed); err != nil || feed != "npm" {
		t.Fatalf("metadata update: %q %v", feed, err)
	}
	if n, err := s.Write(ctx, batch); err != nil || n != 0 {
		t.Fatalf("mixed batch repeated: %d %v", n, err)
	}
}

func TestRepeatDoesNotLockRows(t *testing.T) {
	s := testStore(t)
	o := Observation{SHA256: digest("child"), ParentSHA256: digest("parent"), Path: "p!!file", Filename: "file"}
	if _, err := s.Write(t.Context(), []Observation{o}); err != nil {
		t.Fatal(err)
	}
	tx, err := s.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck // test cleanup
	// Hold UPDATE locks in another transaction. Pure re-observation must not
	// wait on any identity, dictionary, parent, or location row.
	for _, table := range []string{"identities", "relative_paths", "parent_locations", "locations"} {
		if _, err := tx.Exec(t.Context(), "SELECT id FROM "+table+" FOR UPDATE"); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if n, err := s.Write(ctx, []Observation{o}); err != nil || n != 0 {
		t.Fatalf("repeat blocked or wrote: %d %v", n, err)
	}
}

func TestLongRelativePath(t *testing.T) {
	s := testStore(t)
	path := strings.Repeat("long-directory/", 400) + "file.js"
	o := Observation{SHA256: digest("child"), ParentSHA256: digest("parent"), Path: "p!!" + path, Filename: path}
	if _, err := s.Write(t.Context(), []Observation{o}); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := s.Pool.QueryRow(t.Context(), `SELECT path FROM reconstructed`).Scan(&got); err != nil || got != o.Path {
		t.Fatalf("long path: %v", err)
	}
}
