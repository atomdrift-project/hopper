package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/jackc/pgx/v5"
)

// minSize is the smallest file worth a row. Below it there is nothing to
// classify, and every such file costs the same row, queue slot and worker
// round trip as a real one.
const minSize = 6

// Arrival is a file hopper has been shown: where its bytes are, and what
// whoever showed it claims about it.
type Arrival struct {
	Mtime       *time.Time // of the file at Path
	FetchedAt   *time.Time
	PublishedAt *time.Time
	// Path is where the bytes can be read. A path names one file: an arrival
	// at a path another file held takes the path over.
	Path   string
	Source string // who produced it: a walker, a fetcher, "upload"
	Feed   string
	// Label is what the producer vouches for; empty means unknown.
	Label       string
	LabelSource string
	// Name is the release's PURL without its version, when it is one.
	Name    string
	Version string
	URL     string
	SHA256  []byte
	// Provenance is the capture sidecar, as JSON. It is written once.
	Provenance []byte
	Size       int64 // 0 if not known
}

// Ingested counts what one [Store.Ingest] changed.
type Ingested struct {
	Refused   int   // arrivals too small to be worth a row, or naming a path, name or version no row can hold
	New       int64 // files never seen before
	Updated   int64 // known files whose label or identity changed
	Located   int64 // paths added, moved to other bytes, or amended
	Displaced int64 // files that lost their only path to other bytes, and their place in the queue
	Queued    int64 // files queued for a first scan, or raised in the queue
}

// labelRank orders labels by how much they claim. A person's review outranks
// a pool's label, and a pool's outranks a feed's citation.
const labelRank = `(CASE %s WHEN 'inconclusive' THEN 4 WHEN 'dual-use' THEN 4 WHEN 'purgatory' THEN 4
	WHEN 'bad' THEN 3 WHEN 'good' THEN 2 WHEN 'sighted' THEN 1 ELSE 0 END)`

// resolved is what each column of a known sample becomes when the file is
// shown again, in terms of the stored row (old) and the arrival (new). The
// rules:
//
//   - A reviewed label (inconclusive, dual-use, purgatory) is never replaced.
//   - A marker beside the file overrides the pool it sits in, and a pool
//     label returns when the marker is gone.
//   - Good and bad pools disagreeing is bad, with the source "conflict".
//   - Otherwise the label that claims more wins.
//   - The first sidecar supersedes an identity guessed from a filename; after
//     that an arrival only fills what is missing.
var resolved = []struct{ column, value string }{
	{"label", `CASE
		WHEN old.label IN ('inconclusive', 'dual-use', 'purgatory') THEN old.label
		WHEN new.label_source = 'marker' THEN new.label
		WHEN old.label_source = 'marker' THEN new.label
		WHEN (old.label = 'good' AND new.label = 'bad') OR (old.label = 'bad' AND new.label = 'good') THEN 'bad'::label
		WHEN ` + fmt.Sprintf(labelRank, "new.label") + ` > ` + fmt.Sprintf(labelRank, "old.label") + ` THEN new.label
		ELSE old.label END`},
	{"label_source", `CASE
		WHEN old.label IN ('inconclusive', 'dual-use', 'purgatory') THEN old.label_source
		WHEN new.label_source = 'marker' THEN 'marker'
		WHEN old.label_source = 'marker' THEN new.label_source
		WHEN (old.label = 'good' AND new.label = 'bad') OR (old.label = 'bad' AND new.label = 'good') THEN 'conflict'
		WHEN ` + fmt.Sprintf(labelRank, "new.label") + ` > ` + fmt.Sprintf(labelRank, "old.label") + ` THEN new.label_source
		ELSE old.label_source END`},
	{"name_id", `CASE WHEN new.name_id IS NOT NULL
		AND (old.name_id IS NULL OR (old.provenance IS NULL AND new.provenance IS NOT NULL))
		THEN new.name_id ELSE old.name_id END`},
	{"version", `CASE WHEN new.version <> ''
		AND (old.version = '' OR (old.provenance IS NULL AND new.provenance IS NOT NULL))
		THEN new.version ELSE old.version END`},
	{"url", `coalesce(old.url, new.url)`},
	{"size_bytes", `coalesce(old.size_bytes, new.size_bytes)`},
	{"fetched_at", `coalesce(old.fetched_at, new.fetched_at)`},
	{"published_at", `coalesce(old.published_at, new.published_at)`},
}

// sampleSet and sampleChanged render resolved as an UPDATE's assignments and
// as the test for whether any of them would change the row. The test is used
// twice, before the insert and in its conflict clause, so that a file shown
// again unchanged is neither rewritten nor locked. Provenance is written once
// and is never read back to be compared with itself.
var sampleSet, sampleChanged = func() (set, changed string) {
	var sets, olds, news []string
	for _, r := range resolved {
		sets = append(sets, r.column+" = "+r.value)
		olds, news = append(olds, "old."+r.column), append(news, r.value)
	}
	sets = append(sets, "provenance = coalesce(old.provenance, new.provenance)")
	return strings.Join(sets, ",\n"), `(ROW(` + strings.Join(olds, ", ") + `) IS DISTINCT FROM ROW(` + strings.Join(news, ", ") + `)
		OR (old.provenance IS NULL AND new.provenance IS NOT NULL))`
}()

// A path that now holds other bytes starts over; a path seen again keeps who
// first produced it and takes the newer feed and mtime.
const (
	locationSet = `sample_id = new.sample_id,
		source = CASE WHEN old.sample_id <> new.sample_id OR old.source IS NULL THEN new.source ELSE old.source END,
		feed = CASE WHEN old.sample_id <> new.sample_id OR new.feed IS NOT NULL THEN new.feed ELSE old.feed END,
		mtime = CASE WHEN old.sample_id <> new.sample_id THEN new.mtime ELSE coalesce(new.mtime, old.mtime) END,
		seen_at = CASE WHEN old.sample_id <> new.sample_id THEN now() ELSE old.seen_at END`
	locationChanged = `(old.sample_id <> new.sample_id
		OR (old.source IS NULL AND new.source IS NOT NULL)
		OR (new.feed IS NOT NULL AND old.feed IS DISTINCT FROM new.feed)
		OR (new.mtime IS NOT NULL AND old.mtime IS DISTINCT FROM new.mtime))`
)

// against renders an expression written in terms of old and new for a
// statement where the stored row and the incoming one go by other names.
func against(expr, stored, incoming string) string {
	return strings.NewReplacer("old.", stored+".", "new.", incoming+".").Replace(expr)
}

var labels = map[string]bool{
	"unknown": true, "sighted": true, "good": true, "bad": true,
	"inconclusive": true, "dual-use": true, "purgatory": true,
}

// emptySHA256 is the digest of zero bytes: every empty file, whatever its name.
var emptySHA256 = sha256.Sum256(nil)

// storable is s as PostgreSQL will take it: text holds neither a NUL nor
// bytes that are not UTF-8. Names, versions and URLs come from registries,
// so from whoever published the package.
func storable(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
}

// Ingest records files hopper has been shown, all of them or none: each
// file's row, its path, and a place in the queue at the given priority for
// any that nothing has scanned yet. A file a sighting names is queued as
// Sighted whatever that priority is. Showing hopper the same file at the same
// path again writes nothing.
//
// Nothing an arrival carries can fail the batch at the database, where it
// would fail the same way on every retry: text is stored without the bytes
// PostgreSQL refuses, a sidecar it would refuse is left out, to be filled by
// a later one, and an arrival naming a path, name or version too long for a
// row is refused. When one batch shows a file twice the first arrival speaks
// for it and the rest add only their paths; what they claim is heard the next
// time they are shown.
//
// Once the batch commits, the files that arrived named by a sighting, or
// under a newly given release, are marked cited (see [Store.Cite]). An error
// from that alone leaves the batch stored; the counts are returned with it.
func (st *Store) Ingest(ctx context.Context, arrivals []Arrival, priority Priority) (Ingested, error) {
	var (
		got                                  Ingested
		shas                                 [][]byte
		provenance                           []*string
		sizes                                []int64
		lbls, sources, names, versions, urls []string
		paths, producers, feeds              []string
		fetched, published, mtimes           []*time.Time
		distinct                             = map[string]bool{}
	)
	for i := range arrivals {
		a := &arrivals[i]
		label := a.Label
		if label == "" {
			label = "unknown"
		}
		name := NameOf(storable(a.Name))
		switch {
		case len(a.SHA256) != 32:
			return Ingested{}, fmt.Errorf("store: ingest: arrival %d: sha256 is %d bytes", i, len(a.SHA256))
		case !labels[label]:
			return Ingested{}, fmt.Errorf("store: ingest: arrival %d: label %q", i, a.Label)
		case [32]byte(a.SHA256) == emptySHA256 || (a.Size > 0 && a.Size < minSize),
			len(name) > scanresult.MaxName || len(a.Version) > scanresult.MaxVersion,
			// No file is at a path that is not a path, or that no row holds.
			a.Path == "" || len(a.Path) > 1024 || !utf8.ValidString(a.Path) || strings.IndexByte(a.Path, 0) >= 0:
			got.Refused++
			continue
		default:
		}
		shas, sizes, lbls, sources = append(shas, a.SHA256), append(sizes, a.Size), append(lbls, label), append(sources, storable(a.LabelSource))
		names, versions, urls = append(names, name), append(versions, storable(a.Version)), append(urls, storable(a.URL))
		fetched, published = append(fetched, a.FetchedAt), append(published, a.PublishedAt)
		var sidecar *string
		if json.Valid(a.Provenance) && scanresult.CheckJSONB(a.Provenance) == nil {
			text := string(a.Provenance)
			sidecar = &text
		}
		provenance = append(provenance, sidecar)
		paths, mtimes = append(paths, a.Path), append(mtimes, a.Mtime)
		producers, feeds = append(producers, storable(a.Source)), append(feeds, storable(a.Feed))
		if name != "" {
			distinct[name] = true
		}
	}
	if len(shas) == 0 {
		return got, nil
	}
	interned := make([]string, 0, len(distinct))
	for name := range distinct {
		interned = append(interned, name)
	}

	var named []int64 // files new, or newly given a release
	err := pgx.BeginFunc(ctx, st.pool, func(tx pgx.Tx) error {
		if len(interned) > 0 {
			if err := intern(ctx, tx, interned); err != nil {
				return err
			}
		}
		// Rows are taken in digest order, as every writer of samples takes them.
		var nowBad []int64
		err := tx.QueryRow(ctx, `WITH u AS (
				SELECT DISTINCT ON (a.sha) a.sha, nullif(a.size, 0) AS size_bytes, a.label::label AS label,
				       nullif(a.label_source, '') AS label_source,
				       n.id AS name_id, a.version, nullif(a.url, '') AS url, a.fetched_at, a.published_at, a.provenance
				FROM unnest($1::bytea[], $2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
				            $8::timestamptz[], $9::timestamptz[], $10::jsonb[]) WITH ORDINALITY
					AS a(sha, size, label, label_source, name, version, url, fetched_at, published_at, provenance, ord)
				LEFT JOIN names n ON a.name <> '' AND n.name = a.name
				ORDER BY a.sha, a.ord
			), w AS (
			INSERT INTO samples (sha256, size_bytes, label, label_source, name_id, version, url, fetched_at, published_at, provenance)
			SELECT u.sha, u.size_bytes, u.label, u.label_source, u.name_id, u.version, u.url, u.fetched_at, u.published_at, u.provenance
			FROM u LEFT JOIN samples s ON s.sha256 = u.sha
			WHERE s.id IS NULL OR `+against(sampleChanged, "s", "u")+`
			ORDER BY u.sha
			ON CONFLICT (sha256) DO UPDATE SET `+against(sampleSet, "samples", "EXCLUDED")+`
			WHERE `+against(sampleChanged, "samples", "EXCLUDED")+`
			RETURNING id, old.id IS NULL AS fresh, (old.name_id, old.version) IS DISTINCT FROM (name_id, version) AS renamed,
			          label = 'bad' AND old.label IS DISTINCT FROM 'bad' AS now_bad)
			SELECT count(*) FILTER (WHERE fresh), count(*) FILTER (WHERE NOT fresh),
			       coalesce(array_agg(id) FILTER (WHERE fresh OR renamed), '{}'),
			       coalesce(array_agg(id) FILTER (WHERE now_bad AND NOT fresh), '{}')
			FROM w`,
			shas, sizes, lbls, sources, names, versions, urls, fetched, published, provenance).Scan(&got.New, &got.Updated, &named, &nowBad)
		if err != nil {
			return fmt.Errorf("samples: %w", err)
		}
		if len(nowBad) > 0 {
			// A file just labelled bad is triage's business from its last
			// scan on, as if that scan had seen the label.
			if _, err := tx.Exec(ctx, `UPDATE scans SET flagged = true WHERE sample_id = ANY($1) AND NOT flagged`, nowBad); err != nil {
				return fmt.Errorf("flagged: %w", err)
			}
		}

		// The path's row comes back as it was, so a file that has just lost
		// a path to other bytes is known.
		rows, err := tx.Query(ctx, `WITH u AS (
				SELECT DISTINCT ON (a.path) a.path, s.id AS sample_id, nullif(a.source, '') AS source,
				       nullif(a.feed, '') AS feed, a.mtime
				FROM unnest($1::text[], $2::bytea[], $3::text[], $4::text[], $5::timestamptz[]) WITH ORDINALITY
					AS a(path, sha, source, feed, mtime, ord)
				JOIN samples s ON s.sha256 = a.sha
				ORDER BY a.path, a.ord DESC)
			INSERT INTO locations (path, sample_id, source, feed, mtime)
			SELECT u.path, u.sample_id, u.source, u.feed, u.mtime
			FROM u LEFT JOIN locations l ON l.path = u.path
			WHERE l.path IS NULL OR `+against(locationChanged, "l", "u")+`
			ORDER BY u.path
			ON CONFLICT (path) DO UPDATE SET `+against(locationSet, "locations", "EXCLUDED")+`
			WHERE `+against(locationChanged, "locations", "EXCLUDED")+`
			RETURNING old.sample_id, sample_id`,
			paths, shas, producers, feeds, mtimes)
		if err != nil {
			return fmt.Errorf("locations: %w", err)
		}
		var (
			was       *int64
			now       int64
			displaced []int64
		)
		tag, err := pgx.ForEachRow(rows, []any{&was, &now}, func() error {
			if was != nil && *was != now {
				displaced = append(displaced, *was)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("locations: %w", err)
		}
		got.Located = tag.RowsAffected()
		if len(displaced) > 0 {
			// The bytes that were at the path are gone from it. If that was
			// the only place to read them, there is nothing to hand a worker.
			tag, err = tx.Exec(ctx, unqueueUnlocated, displaced)
			if err != nil {
				return fmt.Errorf("displaced: %w", err)
			}
			got.Displaced = tag.RowsAffected()
		}

		// A file already queued at least this high is left out before the
		// insert, so showing hopper its backlog again locks no queue rows.
		tag, err = tx.Exec(ctx, `INSERT INTO queue (sample_id, priority)
			SELECT w.id, w.priority
			FROM (SELECT s.id, CASE
					-- Named by a feed: labelled sighted by its pool, or named
					-- in the sightings ledger.
					WHEN s.label = 'sighted' OR named(s.sha256, s.name_id, s.version) THEN $2::smallint
					WHEN $3::smallint = $4::smallint AND s.size_bytes > $5 THEN $6::smallint
					ELSE $3::smallint END AS priority
				FROM samples s
				WHERE s.sha256 = ANY($1)
				  AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = $7)) w
			LEFT JOIN queue q ON q.sample_id = w.id
			WHERE q.sample_id IS NULL OR q.priority > w.priority
			ORDER BY w.id
			ON CONFLICT (sample_id) DO UPDATE SET priority = EXCLUDED.priority
			WHERE queue.priority > EXCLUDED.priority`,
			shas, int16(QueueSighted), int16(priority), int16(QueueNew), int64(bigFile), int16(QueueBigArchive), atomscan)
		if err != nil {
			return fmt.Errorf("queue: %w", err)
		}
		got.Queued = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return Ingested{}, fmt.Errorf("store: ingest: %w", err)
	}
	if err := st.cite(ctx, named); err != nil {
		return got, fmt.Errorf("store: ingest: %w", err)
	}
	return got, nil
}
