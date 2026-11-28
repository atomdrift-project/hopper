package store

import (
	"maps"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Upgrade remaps a queue written while priorities were 0 to 6 to the spaced
// values, keeping each row's meaning, raises the queued first scans of
// compromised packages, adds what the schema gained, and does all of it
// once.
func TestUpgrade(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	// What this schema.sql makes of what the upgrade adds.
	defs := func() map[string]string {
		t.Helper()
		rows, err := st.pool.Query(ctx, `SELECT 'index', pg_get_indexdef('scans_describable'::regclass)
			UNION ALL SELECT 'column', format_type(atttypid, atttypmod) || ' ' || attnotnull
			FROM pg_attribute WHERE attrelid = 'scans'::regclass AND attname = 'llm_admission'
			UNION ALL SELECT 'check', pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'scans_llm_admission_check'`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				t.Fatal(err)
			}
			out[k] = strings.TrimSuffix(v, " NOT VALID")
		}
		return out
	}
	fresh := defs()
	// Tables as the schema before 2026-11-27 made them.
	if _, err := st.pool.Exec(ctx, `DROP INDEX queue_newest; DROP TABLE llm_attempts; DROP TABLE llm_inputs;
		DROP INDEX scans_describable; ALTER TABLE scans DROP COLUMN llm_admission`); err != nil {
		t.Fatal(err)
	}
	old := map[string]int16{
		"sighted": 0, "upload": 1, "requested": 2, "big": 3, "new": 4, "repair": 5, "stale": 6,
		"evil new": 4, "evil big": 3, "evil requested": 2, "evil stuck": 4,
	}
	for name := range old {
		r := Arrival{SHA256: digestOf(name), Size: 100, Path: "pool/" + name}
		if strings.HasPrefix(name, "evil ") {
			r.Name, r.Version = "pkg:npm/evil", name
		}
		ingest(ctx, t, st, QueueNew, r)
	}
	// Called malicious after it was queued, before the upgrade raised it.
	if _, err := st.pool.Exec(ctx, `INSERT INTO sightings (source, subject, affected) VALUES ('osv', 'pkg:npm/evil', '0.0.1')`); err != nil {
		t.Fatal(err)
	}
	for name, p := range old {
		if _, err := st.pool.Exec(ctx, `UPDATE queue SET priority = $2, attempts = CASE WHEN $3 THEN 8 ELSE 0 END
			WHERE sample_id = (SELECT id FROM samples WHERE sha256 = $1)`, digestOf(name), p, name == "evil stuck"); err != nil {
			t.Fatal(err)
		}
	}

	// A replica's read-only session changes nothing.
	cfg := st.pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	ro, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	replica, err := New(ro)
	if err != nil {
		t.Fatal(err)
	}
	if err := replica.Upgrade(ctx); err != nil {
		t.Fatalf("upgrade on a read-only session: %v", err)
	}
	want := map[string]Priority{}
	for name, p := range old {
		want[hexOf(digestOf(name))] = Priority(p)
	}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Fatalf("a read-only upgrade changed the queue: %v, want %v", got, want)
	}

	if err := st.Upgrade(ctx); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Priority{
		"sighted": QueueSighted, "upload": QueueUpload, "requested": QueueRequested, "big": QueueBigArchive,
		"new": QueueNew, "repair": QueueRepair, "stale": QueueStale,
		"evil new": QueueCompromised, "evil big": QueueCompromised, "evil requested": QueueRequested,
		"evil stuck": QueueCompromised,
	} {
		want[hexOf(digestOf(name))] = p
	}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("after the upgrade: %v, want %v", got, want)
	}
	var missing int
	if err := st.pool.QueryRow(ctx, `SELECT (to_regclass('queue_newest') IS NULL)::int + (to_regclass('llm_attempts') IS NULL)::int +
		(to_regclass('llm_inputs') IS NULL)::int + (to_regclass('scans_describable') IS NULL)::int`).
		Scan(&missing); err != nil || missing != 0 {
		t.Errorf("%d relations missing after the upgrade, %v", missing, err)
	}
	if got := defs(); len(fresh) != 3 || !maps.Equal(got, fresh) {
		t.Errorf("scans after the upgrade %v, want what schema.sql makes, %v", got, fresh)
	}

	// Again, and on rows written since: nothing moves.
	release(ctx, t, st, "after", "", "", "")
	want[hexOf(digestOf("after"))] = QueueNew
	if err := st.Upgrade(ctx); err != nil {
		t.Fatal(err)
	}
	if got := priorities(ctx, t, st); !maps.Equal(got, want) {
		t.Errorf("a second upgrade moved rows: %v, want %v", got, want)
	}
}

// Upgrade gives samples made before 2026-11-28 the label and route indexes
// and the insert-driven vacuum setting, exactly as schema.sql spells them,
// rebuilds an index a failed concurrent build left invalid, and leaves a
// valid one alone.
func TestUpgradeSamplesIndexes(t *testing.T) {
	st := open(t)
	ctx := t.Context()
	defs := func() map[string]string {
		t.Helper()
		rows, err := st.pool.Query(ctx, `SELECT 'samples_label', pg_get_indexdef('samples_label'::regclass)
			UNION ALL SELECT 'samples_labeled_route', pg_get_indexdef('samples_labeled_route'::regclass)
			UNION ALL SELECT relname, array_to_string(reloptions, ',') FROM pg_class
			WHERE oid IN ('samples'::regclass, 'contents'::regclass, 'locations'::regclass)`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				t.Fatal(err)
			}
			out[k] = v
		}
		return out
	}
	fresh := defs()
	if len(fresh) != 5 {
		t.Fatalf("schema.sql made %v", fresh)
	}
	if _, err := st.pool.Exec(ctx, `DROP INDEX samples_label; DROP INDEX samples_labeled_route;
		ALTER TABLE samples RESET (autovacuum_vacuum_insert_scale_factor);
		ALTER TABLE contents RESET (autovacuum_vacuum_insert_scale_factor);
		ALTER TABLE locations RESET (autovacuum_vacuum_insert_scale_factor)`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := st.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
		if got := defs(); !maps.Equal(got, fresh) {
			t.Fatalf("upgraded:\n%v\nfresh:\n%v", got, fresh)
		}
	}

	// What an interrupted CREATE INDEX CONCURRENTLY leaves. Marking it by hand
	// needs a superuser; a test database without one cannot stage it.
	if _, err := st.pool.Exec(ctx, `UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'samples_label'::regclass`); err != nil {
		t.Skipf("cannot mark an index invalid here: %v", err)
	}
	var before uint32
	if err := st.pool.QueryRow(ctx, `SELECT 'samples_label'::regclass::oid`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := st.Upgrade(ctx); err != nil {
		t.Fatal(err)
	}
	var after uint32
	var valid bool
	if err := st.pool.QueryRow(ctx, `SELECT indexrelid::oid, indisvalid FROM pg_index
		WHERE indexrelid = 'samples_label'::regclass`).Scan(&after, &valid); err != nil {
		t.Fatal(err)
	}
	if after == before || !valid {
		t.Fatalf("invalid index not rebuilt: oid %d -> %d, valid=%v", before, after, valid)
	}
}
