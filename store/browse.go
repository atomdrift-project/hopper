package store

// The reads of a service that shows the store to people (prism): a file with
// every scanner's opinion, what an archive holds and which archives hold a
// file, a feed of scanned files and the facets that filter it, the reports
// triage filed, and counts. They only read, and none of them reads a stored
// report unless asked (Reports): a top-level report can run to tens of
// megabytes.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper/pkgparse"
	"github.com/jackc/pgx/v5"
)

// scannerNames is the scanners table by id.
var scannerNames = func() map[int16]string {
	m := map[int16]string{atomscan: "atomscan"}
	for _, by := range []map[string]int16{jurors, outside} {
		for name, id := range by {
			m[id] = name
		}
	}
	return m
}()

// Opinion is one scanner's current opinion of a file: a verdicts row.
type Opinion struct {
	FormedAt time.Time
	// FiresAt is the tightest false-positive budget at which the opinion
	// grades hostile: lower is worse, -1 never fires, nil unmeasured.
	FiresAt *int
	Outcome string
	// Class is benign, suspicious or hostile; empty when the scanner reached
	// none.
	Class   string
	Ruleset string
	// Summary is the rest of the scanner's own scale as it sent it: atomscan's
	// reason and strongest findings, the model's probability, the
	// interpreter's reading and confidence.
	Summary json.RawMessage
}

// Location is a path the file is held at on disk.
type Location struct {
	SeenAt time.Time
	Mtime  *time.Time
	Path   string
	Source string
	Feed   string
}

// Scan is a scanned artifact's last scan.
type Scan struct {
	At      time.Time
	Ruleset string
	Engine  string
	Flagged bool
}

// Sample is what the store holds about one file.
type Sample struct {
	CreatedAt   time.Time
	FetchedAt   *time.Time
	PublishedAt *time.Time
	// Scan is nil for a file only ever seen inside another.
	Scan *Scan
	// Location is the newest path the file is held at; nil when none.
	Location *Location
	// Opinions holds each scanner's row by scanner name ("atomscan", "floor",
	// "ml", "llm", "clamav", …). A scanner with no row has made no statement.
	Opinions map[string]Opinion
	// Provenance is how the bytes arrived (fetch, package, artifact, registry).
	Provenance json.RawMessage
	// Ident is the identity block the file claims (claims.ident); nil when
	// no scan has read one.
	Ident json.RawMessage
	// Name is the release's package URL without a version, or the URL the
	// file was fetched from; empty for a loose file.
	Name        string
	Version     string
	Type        string
	Label       string
	LabelSource string
	URL         string
	SHA256      []byte
	ID          int64
	Size        int64 // 0 when unknown
	Cited       bool  // some sighting names the file (samples.cited)
}

// EcosystemOf returns the runtime ecosystem of a file filed under name with
// file type fileType (pkgparse's vocabulary: "javascript", "windows", …):
// its package URL type's, else its file type's. "" when neither says.
func EcosystemOf(name, fileType string) string {
	if t := purlType(name); t != "" {
		if eco := pkgparse.PURLEcosystem(t); eco != "" {
			return eco
		}
	}
	return pkgparse.NormalizeEcosystem(fileType)
}

// purlType returns the type of a package URL ("npm" for pkg:npm/left-pad).
func purlType(name string) string {
	rest, ok := strings.CutPrefix(name, "pkg:")
	if !ok {
		return ""
	}
	t, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(t)
}

// newestLocation is a LATERAL subquery for the newest path a sample (s) is
// held at; locations_sample serves it.
const newestLocation = `LEFT JOIN LATERAL (SELECT x.path, coalesce(x.source, '') AS source, coalesce(x.feed, '') AS feed,
		x.mtime, x.seen_at FROM locations x WHERE x.sample_id = s.id ORDER BY x.seen_at DESC, x.path LIMIT 1) l ON true`

// Sample returns what the store holds about exact bytes.
func (st *Store) Sample(ctx context.Context, sha256 []byte) (*Sample, error) {
	var (
		s                       Sample
		scanned                 *time.Time
		ruleset, engine         *string
		flagged                 *bool
		path, source, feed      *string
		mtime, seen             *time.Time
		ident, provenance       []byte
		published, fetched      *time.Time
		name, fileType, labelBy *string
	)
	err := st.pool.QueryRow(ctx, `SELECT s.id, s.sha256, coalesce(s.size_bytes, 0), s.file_type, s.label::text,
			s.label_source, s.created_at, n.name, s.version, s.published_at, coalesce(s.url, ''), s.fetched_at,
			s.provenance, s.cited, c.ident, sc.scanned_at, sc.ruleset, sc.engine, sc.flagged,
			l.path, l.source, l.feed, l.mtime, l.seen_at
		FROM samples s
		LEFT JOIN names n ON n.id = s.name_id
		LEFT JOIN claims c ON c.sample_id = s.id
		LEFT JOIN scans sc ON sc.sample_id = s.id
		`+newestLocation+`
		WHERE s.sha256 = $1`, sha256).Scan(&s.ID, &s.SHA256, &s.Size, &fileType, &s.Label,
		&labelBy, &s.CreatedAt, &name, &s.Version, &published, &s.URL, &fetched,
		&provenance, &s.Cited, &ident, &scanned, &ruleset, &engine, &flagged,
		&path, &source, &feed, &mtime, &seen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: sample: %w", err)
	}
	s.Name, s.Type, s.LabelSource = deref(name), deref(fileType), deref(labelBy)
	s.CreatedAt, s.PublishedAt, s.FetchedAt = s.CreatedAt.UTC(), utc(published), utc(fetched)
	s.Provenance, s.Ident = json.RawMessage(provenance), json.RawMessage(ident)
	if scanned != nil {
		s.Scan = &Scan{At: scanned.UTC(), Ruleset: deref(ruleset), Engine: deref(engine), Flagged: flagged != nil && *flagged}
	}
	if path != nil {
		s.Location = &Location{Path: *path, Source: deref(source), Feed: deref(feed), Mtime: utc(mtime), SeenAt: seen.UTC()}
	}
	opinions, err := st.Opinions(ctx, []int64{s.ID})
	if err != nil {
		return nil, err
	}
	s.Opinions = opinions[s.ID]
	return &s, nil
}

// Opinions returns every scanner's opinion of each sample, by sample id and
// then scanner name. A sample no scanner has judged is absent.
func (st *Store) Opinions(ctx context.Context, ids []int64) (map[int64]map[string]Opinion, error) {
	out := make(map[int64]map[string]Opinion, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := st.pool.Query(ctx, `SELECT sample_id, scanner_id, formed_at, outcome::text, coalesce(class::text, ''),
			fires_at, ruleset, summary
		FROM verdicts WHERE sample_id = ANY ($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("store: opinions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id      int64
			scanner int16
			o       Opinion
			fires   *int16
			summary []byte
		)
		if err := rows.Scan(&id, &scanner, &o.FormedAt, &o.Outcome, &o.Class, &fires, &o.Ruleset, &summary); err != nil {
			return nil, fmt.Errorf("store: opinions: %w", err)
		}
		o.FormedAt, o.FiresAt, o.Summary = o.FormedAt.UTC(), widen(fires), json.RawMessage(summary)
		if out[id] == nil {
			out[id] = map[string]Opinion{}
		}
		out[id][scannerNames[scanner]] = o
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: opinions: %w", err)
	}
	return out, nil
}

// Member is a file an archive holds, directly or inside one of its members.
type Member struct {
	Path   string // where it sits in Parent
	Type   string
	SHA256 []byte
	ID     int64
	Parent int64 // the sample id of the archive that lists it
	Size   int64 // 0 when unknown
	Depth  int   // 1 for the archive's own members
}

// maxMemberDepth bounds how far Members walks down: nesting deeper than this
// is a zip bomb, or an archive that holds itself further down.
const maxMemberDepth = 16

// Members lists what the archive with sample id holds, breadth first: its
// members in the order its list gives them, then theirs, at most limit in
// all. truncated reports that more exist.
func (st *Store) Members(ctx context.Context, id int64, limit int) (members []Member, truncated bool, err error) {
	limit = max(limit, 1)
	rows, err := st.pool.Query(ctx, `WITH RECURSIVE t (parent_id, id, path, depth, ord) AS (
			SELECT k.parent_id, m.id, m.path, 1, m.ord
			FROM contents k, unnest(k.child_ids, k.paths) WITH ORDINALITY AS m (id, path, ord)
			WHERE k.parent_id = $1
			UNION ALL
			SELECT k.parent_id, m.id, m.path, t.depth + 1, m.ord
			FROM t JOIN contents k ON k.parent_id = t.id,
				unnest(k.child_ids, k.paths) WITH ORDINALITY AS m (id, path, ord)
			WHERE t.depth < $3)
		SELECT t.parent_id, t.id, t.path, t.depth, s.sha256, coalesce(s.size_bytes, 0), coalesce(s.file_type, '')
		FROM (SELECT parent_id, id, path, depth, ord FROM t LIMIT $2) t JOIN samples s ON s.id = t.id
		ORDER BY t.depth, t.parent_id, t.ord`, id, limit+1, maxMemberDepth)
	if err != nil {
		return nil, false, fmt.Errorf("store: members: %w", err)
	}
	members, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Member, error) {
		var m Member
		err := row.Scan(&m.Parent, &m.ID, &m.Path, &m.Depth, &m.SHA256, &m.Size, &m.Type)
		return m, err
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: members: %w", err)
	}
	if len(members) > limit {
		return members[:limit], true, nil
	}
	return members, false, nil
}

// Reports returns atomscan's stored report of each sample, as it was
// uploaded, by sample id. A sample with none is absent.
func (st *Store) Reports(ctx context.Context, ids []int64) (map[int64][]byte, error) {
	out := make(map[int64][]byte, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := st.pool.Query(ctx, `SELECT sample_id, detail FROM verdicts
		WHERE sample_id = ANY ($1) AND scanner_id = $2 AND detail IS NOT NULL`, ids, atomscan)
	if err != nil {
		return nil, fmt.Errorf("store: reports: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id     int64
			packed []byte
		)
		if err := rows.Scan(&id, &packed); err != nil {
			return nil, fmt.Errorf("store: reports: %w", err)
		}
		report, err := st.dec.DecodeAll(packed, nil)
		if err != nil {
			return nil, fmt.Errorf("store: report of sample %d: %w", id, err)
		}
		out[id] = report
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: reports: %w", err)
	}
	return out, nil
}

// Parent is an archive that holds a file.
type Parent struct {
	ScannedAt time.Time // zero if never scanned on its own
	FiresAt   *int      // atomscan's level; nil unmeasured
	Location  *Location
	Path      string // where the file sits in it
	Name      string
	Version   string
	Type      string
	Class     string // atomscan's class; empty when none
	Filename  string // the name it arrived under (provenance), if known
	SHA256    []byte
	ID        int64
}

// Parents returns up to limit archives that list exact bytes among their
// members, the most recently scanned first.
func (st *Store) Parents(ctx context.Context, sha256 []byte, limit int) ([]Parent, error) {
	// s is the archive, as newestLocation names it; c the file it holds.
	rows, err := st.pool.Query(ctx, `SELECT s.id, s.sha256, coalesce(n.name, ''), s.version, coalesce(s.file_type, ''),
			m.path, coalesce(v.class::text, ''), v.fires_at, sc.scanned_at,
			coalesce(s.provenance->'artifact'->>'filename', ''), l.path, l.source, l.feed, l.mtime, l.seen_at
		FROM samples c
		JOIN contents k ON k.child_ids @> ARRAY[c.id]
		CROSS JOIN LATERAL (SELECT u.path FROM unnest(k.child_ids, k.paths) u (id, path) WHERE u.id = c.id LIMIT 1) m
		JOIN samples s ON s.id = k.parent_id
		LEFT JOIN names n ON n.id = s.name_id
		LEFT JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $3
		LEFT JOIN scans sc ON sc.sample_id = s.id
		`+newestLocation+`
		WHERE c.sha256 = $1
		ORDER BY sc.scanned_at DESC NULLS LAST, s.id DESC
		LIMIT $2`, sha256, max(limit, 1), atomscan)
	if err != nil {
		return nil, fmt.Errorf("store: parents: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Parent, error) {
		var (
			p                  Parent
			fires              *int16
			scanned            *time.Time
			path, source, feed *string
			mtime, seen        *time.Time
		)
		err := row.Scan(&p.ID, &p.SHA256, &p.Name, &p.Version, &p.Type, &p.Path, &p.Class, &fires, &scanned,
			&p.Filename, &path, &source, &feed, &mtime, &seen)
		p.FiresAt = widen(fires)
		if scanned != nil {
			p.ScannedAt = scanned.UTC()
		}
		if path != nil {
			p.Location = &Location{Path: *path, Source: deref(source), Feed: deref(feed), Mtime: utc(mtime), SeenAt: seen.UTC()}
		}
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("store: parents: %w", err)
	}
	return out, nil
}

// FiledReport is a report triage filed about a file (the reports table).
type FiledReport struct {
	CreatedAt  time.Time
	Type       string
	Content    string
	Provider   string
	ID         int64
	DurationMS int
}

// LatestReport returns the newest report of reportType filed about exact
// bytes.
func (st *Store) LatestReport(ctx context.Context, sha256 []byte, reportType string) (*FiledReport, error) {
	var r FiledReport
	err := st.pool.QueryRow(ctx, `SELECT r.id, r.report_type, r.content, r.provider, r.duration_ms, r.created_at
		FROM samples s JOIN reports r ON r.sample_id = s.id
		WHERE s.sha256 = $1 AND r.report_type = $2
		ORDER BY r.created_at DESC LIMIT 1`, sha256, reportType).Scan(
		&r.ID, &r.Type, &r.Content, &r.Provider, &r.DurationMS, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: report: %w", err)
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return &r, nil
}

// Count returns how many samples have ids above after, and the highest id
// there is: a reader counts the store once (after 0), then only what arrived
// since, an index range over the new rows.
func (st *Store) Count(ctx context.Context, after int64) (n, maxID int64, err error) {
	err = st.pool.QueryRow(ctx, `SELECT count(*), coalesce(max(id), $1::bigint) FROM samples WHERE id > $1::bigint`,
		after).Scan(&n, &maxID)
	if err != nil {
		return 0, 0, fmt.Errorf("store: count: %w", err)
	}
	return n, maxID, nil
}

// Named returns the names, of those given, that some sample is filed under,
// spelled as they were given. Names are spelled as NameOf spells them.
func (st *Store) Named(ctx context.Context, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	rows, err := st.pool.Query(ctx, `SELECT n.name FROM names n
		WHERE n.name = ANY ($1) AND EXISTS (SELECT 1 FROM samples s WHERE s.name_id = n.id)
		ORDER BY n.name`, names)
	if err != nil {
		return nil, fmt.Errorf("store: named: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("store: named: %w", err)
	}
	return out, nil
}

// FeedQuery selects scanned files for a feed, newest first. Zero fields
// match everything.
type FeedQuery struct {
	// Since and Until bound when the store learned of the file, [Since, Until).
	Since time.Time
	Until time.Time
	// Name and Version pin a release; Names lists names to keep, any of them.
	// All are spelled as NameOf spells them.
	Name    string
	Version string
	// Ecosystem is a runtime ecosystem, as EcosystemOf names them.
	Ecosystem string
	// Feed is the feed the file's newest location came from.
	Feed string
	// Search matches an exact lowercase sha256, an exact name, or a
	// case-insensitive substring of the name a file arrived under or a path
	// it is held at.
	Search string
	// ClaimName and ClaimSigner keep files whose identity block claims this
	// name or signer, inside archives too: the executable that carries a
	// signer's claim sits inside its installers.
	ClaimName   string
	ClaimSigner string
	Label       string
	Names       []string
	// Classes are atomscan classes to keep; empty keeps every file atomscan
	// reached a class on.
	Classes []string
	Offset  int
	Limit   int // clamped to 1–1000
	// Cited keeps files some sighting names.
	Cited bool
	// TopLevel keeps files no archive lists among its members.
	TopLevel bool
}

// FeedRow is one file of a feed.
type FeedRow struct {
	CreatedAt time.Time
	ScannedAt time.Time // zero for a member that was never scanned alone
	FiresAt   *int      // atomscan's level
	MLProb    *float64  // the model's probability, when it gave one
	LLMConf   *float64  // the interpreter's confidence, when it read the file
	Name      string
	Version   string
	Type      string
	Label     string
	URL       string
	// Filename is the name the file arrived under (provenance), else empty.
	Filename string
	// Path, Source and Feed are its newest location; empty when none.
	Path     string
	Source   string
	Feed     string
	Class    string // atomscan's
	Reason   string // atomscan's sentence, when it gave one
	LLMClass string // the interpreter's grade
	LLMWhy   string // the interpreter's reading
	// RegistryTitle, RegistryDescription (up to 300 characters) and
	// RegistryDownloads come from the registry record in the provenance.
	RegistryTitle       string
	RegistryDescription string
	Top                 []Finding // atomscan's strongest findings
	SHA256              []byte
	ID                  int64
	RegistryDownloads   int64
	Cited               bool
}

// Feed returns the files a query selects, newest first (by sample id, the
// order the store learned of them). Without a claim to match, it reads only
// scanned artifacts, walking scans' key down; with one, it reads the files
// claiming it, members included.
func (st *Store) Feed(ctx context.Context, q *FeedQuery) ([]FeedRow, error) {
	var ids idRange
	var err error
	if !q.Since.IsZero() {
		if ids.lo, err = st.idAt(ctx, q.Since); err != nil {
			return nil, err
		}
	}
	if !q.Until.IsZero() {
		if ids.hi, err = st.idAt(ctx, q.Until); err != nil {
			return nil, err
		}
	}
	query, args := feedSQL(q, ids)
	rows, err := st.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: feed: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FeedRow, error) {
		var (
			r                    FeedRow
			fires                *int16
			scanned              *time.Time
			sum, llm             []byte
			path, source, feed   *string
			mlProb               *float64
			downloads            *float64
			title, desc, fname   string
			name, fileType, ucls *string
		)
		err := row.Scan(&r.ID, &r.SHA256, &name, &r.Version, &fileType, &r.Label, &r.CreatedAt, &r.URL, &r.Cited,
			&fname, &path, &source, &feed, &r.Class, &fires, &sum, &mlProb, &ucls, &llm, &scanned,
			&title, &desc, &downloads)
		if err != nil {
			return r, err
		}
		r.Name, r.Type, r.LLMClass = deref(name), deref(fileType), deref(ucls)
		r.Filename, r.RegistryTitle, r.RegistryDescription = fname, title, desc
		r.Path, r.Source, r.Feed = deref(path), deref(source), deref(feed)
		r.CreatedAt, r.FiresAt, r.MLProb = r.CreatedAt.UTC(), widen(fires), mlProb
		if downloads != nil {
			r.RegistryDownloads = int64(*downloads)
		}
		if scanned != nil {
			r.ScannedAt = scanned.UTC()
		}
		var atom summary
		if len(sum) > 0 && json.Unmarshal(sum, &atom) == nil {
			r.Reason, r.Top = atom.Reason, atom.Top
		}
		var in struct {
			Conf   *float64 `json:"conf"`
			Reason string   `json:"reason"`
		}
		if len(llm) > 0 && json.Unmarshal(llm, &in) == nil {
			r.LLMWhy, r.LLMConf = in.Reason, in.Conf
		}
		return r, nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: feed: %w", err)
	}
	return out, nil
}

// windowSlack is how far past a window's id bounds Feed still looks: ids are
// taken by concurrent writers whose clocks and commits interleave, so a row
// created inside the window can sit just outside its id range.
const windowSlack = 10000

// idRange bounds sample ids, [lo, hi); zero leaves an end open.
type idRange struct{ lo, hi int64 }

// idAt returns the lowest sample id created at or after t, by bisecting the
// key. Ids are handed out as files arrive, so created_at rises with them, and
// a window on one is a range of the other: a feed window then reads only its
// own rows, where an index on created_at would cost every insert to save it.
// The window's own predicate still decides each row.
func (st *Store) idAt(ctx context.Context, t time.Time) (int64, error) {
	var lo, hi int64
	if err := st.pool.QueryRow(ctx, `SELECT coalesce(min(id), 0), coalesce(max(id), 0) + 1 FROM samples`).Scan(&lo, &hi); err != nil {
		return 0, fmt.Errorf("store: feed window: %w", err)
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		var (
			id int64
			at time.Time
		)
		err := st.pool.QueryRow(ctx, `SELECT id, created_at FROM samples WHERE id >= $1 ORDER BY id LIMIT 1`, mid).Scan(&id, &at)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			hi = mid
		case err != nil:
			return 0, fmt.Errorf("store: feed window: %w", err)
		case at.Before(t):
			lo = id + 1
		default:
			hi = mid
		}
	}
	return lo, nil
}

// feedSQL builds Feed's statement. Each filter is a literal predicate with its
// value bound, so a generic plan still sees which ones apply. ids is the
// window's id range (idAt).
func feedSQL(filter *FeedQuery, ids idRange) (query string, args []any) {
	bind := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	from := `scans sc JOIN samples s ON s.id = sc.sample_id`
	key := `sc.sample_id` // the driving table's, so its key serves the order and the window
	var where []string
	if filter.ClaimName != "" || filter.ClaimSigner != "" {
		from = `claims c JOIN samples s ON s.id = c.sample_id LEFT JOIN scans sc ON sc.sample_id = s.id`
		key = `c.sample_id`
		if filter.ClaimName != "" {
			where = append(where, "c.name = "+bind(filter.ClaimName))
		}
		if filter.ClaimSigner != "" {
			where = append(where, "c.signer = "+bind(filter.ClaimSigner))
		}
	}
	atom := bind(int16(atomscan))
	if len(filter.Classes) > 0 {
		// The enum, not its text, so verdicts_flagged can serve a class.
		where = append(where, "v.class = ANY ("+bind(filter.Classes)+"::class[])")
	} else {
		where = append(where, "v.class IS NOT NULL")
	}
	where = append(where, "s.file_type IS DISTINCT FROM 'registry'")
	if filter.Ecosystem != "" {
		spellings := pkgparse.EcosystemSpellings(filter.Ecosystem)
		where = append(where, `CASE WHEN n.name LIKE 'pkg:%'
			THEN lower(split_part(substr(n.name, 5), '/', 1)) = ANY (`+bind(spellings)+`)
			ELSE s.file_type = ANY (`+bind(spellings)+`) END`)
	}
	if filter.Feed != "" {
		where = append(where, "l.feed = "+bind(filter.Feed))
	}
	if filter.Name != "" {
		where = append(where, "n.name = "+bind(filter.Name))
	}
	if filter.Version != "" {
		where = append(where, "s.version = "+bind(filter.Version))
	}
	if len(filter.Names) > 0 {
		where = append(where, "n.name = ANY ("+bind(filter.Names)+")")
	}
	if term := strings.ToLower(strings.TrimSpace(filter.Search)); term != "" {
		// A digest is one index probe, and nothing else spells 64 hex
		// characters; a substring has no index to use and reads the feed in
		// order until it has a page or the caller's deadline passes.
		if digest, err := hex.DecodeString(term); err == nil && len(digest) == 32 {
			where = append(where, "s.sha256 = "+bind(digest))
		} else {
			pattern := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(term) + "%"
			where = append(where, "(n.name = "+bind(term)+
				" OR s.provenance->'artifact'->>'filename' ILIKE "+bind(pattern)+
				" OR EXISTS (SELECT 1 FROM locations x WHERE x.sample_id = s.id AND x.path ILIKE "+bind(pattern)+"))")
		}
	}
	if filter.Label != "" {
		where = append(where, "s.label::text = "+bind(filter.Label))
	}
	if filter.Cited {
		where = append(where, "s.cited")
	}
	if filter.TopLevel {
		where = append(where, "NOT EXISTS (SELECT 1 FROM contents k WHERE k.child_ids @> ARRAY[s.id])")
	}
	if !filter.Since.IsZero() {
		where = append(where, key+" >= "+bind(ids.lo-windowSlack), "s.created_at >= "+bind(filter.Since))
	}
	if !filter.Until.IsZero() {
		where = append(where, key+" < "+bind(ids.hi+windowSlack), "s.created_at < "+bind(filter.Until))
	}
	query = `SELECT s.id, s.sha256, n.name, s.version, s.file_type, s.label::text, s.created_at, coalesce(s.url, ''), s.cited,
			coalesce(s.provenance->'artifact'->>'filename', ''), l.path, l.source, l.feed,
			coalesce(v.class::text, ''), v.fires_at, v.summary,
			CASE WHEN jsonb_typeof(ml.summary->'prob') = 'number' THEN (ml.summary->>'prob')::float8 END,
			llm.class::text, llm.summary, sc.scanned_at,
			coalesce(s.provenance->'registry'->'record'->>'title', ''),
			coalesce(left(s.provenance->'registry'->'record'->>'description', 300), ''),
			CASE WHEN jsonb_typeof(s.provenance->'registry'->'record'->'downloads_total') = 'number'
				THEN (s.provenance->'registry'->'record'->>'downloads_total')::float8 END
		FROM ` + from + `
		LEFT JOIN names n ON n.id = s.name_id
		JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = ` + atom + `
		LEFT JOIN verdicts ml ON ml.sample_id = s.id AND ml.scanner_id = 3
		LEFT JOIN verdicts llm ON llm.sample_id = s.id AND llm.scanner_id = 4
		` + newestLocation + `
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ` + key + ` DESC
		LIMIT ` + bind(max(1, min(filter.Limit, 1000))) + ` OFFSET ` + bind(max(filter.Offset, 0))
	return query, args
}

// Facets returns the runtime ecosystems and feeds of the files scanned since:
// the choices a feed offers to filter by, sorted.
func (st *Store) Facets(ctx context.Context, since time.Time) (ecosystems, feeds []string, err error) {
	rows, err := st.pool.Query(ctx, `SELECT DISTINCT coalesce(n.name LIKE 'pkg:%', false),
			coalesce(lower(split_part(substr(n.name, 5), '/', 1)), ''),
			coalesce(s.file_type, ''), coalesce(l.feed, '')
		FROM scans sc JOIN samples s ON s.id = sc.sample_id
		LEFT JOIN names n ON n.id = s.name_id
		`+newestLocation+`
		WHERE sc.scanned_at >= $1`, since)
	if err != nil {
		return nil, nil, fmt.Errorf("store: facets: %w", err)
	}
	defer rows.Close()
	ecos, fds := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var (
			pkg         bool
			t, ft, feed string
		)
		if err := rows.Scan(&pkg, &t, &ft, &feed); err != nil {
			return nil, nil, fmt.Errorf("store: facets: %w", err)
		}
		name := ""
		if pkg {
			name = "pkg:" + t + "/"
		}
		if eco := EcosystemOf(name, ft); eco != "" {
			ecos[eco] = true
		}
		if feed != "" {
			fds[feed] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("store: facets: %w", err)
	}
	return slices.Sorted(maps.Keys(ecos)), slices.Sorted(maps.Keys(fds)), nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func widen(p *int16) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}
