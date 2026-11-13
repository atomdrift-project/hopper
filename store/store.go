// Package store reads and writes hopper's verdict schema: samples, one
// verdict per scanner, archive contents and references, the scan queue and
// the triage queues. See PLAN.md for the design and schema.sql for the
// tables.
//
// A sample is identified by its sha256 (32 bytes) or, for a package release,
// by a name (a PURL without its version) and a version. What a scanner
// concluded lives in verdicts; atomscan's row is the one lookups serve.
package store

import (
	"cmp"
	"context"
	_ "embed" // for Schema
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper/pkgparse"
	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
)

// Schema is the DDL that creates the verdict schema in an empty database.
//
//go:embed schema.sql
var Schema string

// ErrNotFound reports that no sample matches the key.
var ErrNotFound = errors.New("store: not found")

// atomscan is the scanner whose verdict a lookup serves; see the scanners table.
const atomscan = 1

// jurors maps a juror's name in a result to its row in the scanners table,
// and outside does the same for the scanners that are not atomdrift's. Both
// name every scanner package scanresult lets a result carry.
var (
	jurors  = map[string]int16{"floor": 2, "ml": 3, "llm": 4, "drift_heuristic": 5, "drift_llm": 8}
	outside = map[string]int16{"clamav": 6, "malcontent": 7, "guarddog": 9}
)

// NameOf spells a package name as every table that holds one does: canonical,
// without a version, and without qualifiers other than repository_url. It is
// the sightings ledger's spelling of a package subject (normalizeSubject in
// hopper.go), so names, refs and sightings join by equality. A URL is kept as
// it is.
func NameOf(s string) string {
	if !strings.HasPrefix(s, "pkg:") {
		return s
	}
	return pkgparse.VersionlessPURL(pkgparse.CanonicalizePURL(s))
}

// Finding is one of a file's strongest traits: crit 4 is suspicious, 5 hostile.
type Finding = scanresult.Finding

// Record is atomscan's current verdict on one file, as a lookup serves it.
type Record struct {
	// ScannedAt is when the verdict was last confirmed; zero if never scanned.
	ScannedAt time.Time
	// FiresAt is the tightest false-positive budget at which the file grades
	// hostile: lower is worse, -1 never fires, nil means no level was measured.
	FiresAt *int
	// Name is the release's PURL without a version, empty for a loose file.
	Name    string
	Version string
	// Class is benign, suspicious or hostile; empty when atomscan reached none.
	Class string
	// Ruleset is the analyzer judgment the verdict was produced under, and
	// Engine the scan build. A build can change without the judgment changing.
	Ruleset  string
	Engine   string
	Reason   string
	Findings []Finding
	SHA256   []byte
	ID       int64
	// Analyzed is false when the bytes are known but nothing has scanned them.
	Analyzed bool
}

// summary is the part of atomscan's verdict summary a lookup reads. It is at
// most 1 KB and stored inline, and recordColumns leave the report out, so
// serving a record never reads one.
type summary struct {
	Engine string    `json:"eng"`
	Reason string    `json:"reason"`
	Top    []Finding `json:"top"`
}

// Store reads and writes the verdict schema through a connection pool.
type Store struct {
	pool *pgxpool.Pool
	enc  *zstd.Encoder // reports are compressed here, not by PostgreSQL
	dec  *zstd.Decoder
	// KeepOrphans, set before the Store is used, keeps the verdicts of
	// members a write leaves in no archive's list. The migration sets it:
	// version 7 reports list different members of the same nested
	// container from each archive that holds it, so a list rewritten from
	// another archive's report says nothing about the members it lacks.
	KeepOrphans bool
}

// New returns a Store that uses pool. The caller owns the pool.
func New(pool *pgxpool.Pool) (*Store, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, fmt.Errorf("store: zstd encoder: %w", err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(scanresult.MaxLine))
	if err != nil {
		return nil, fmt.Errorf("store: zstd decoder: %w", err)
	}
	return &Store{pool: pool, enc: enc, dec: dec}, nil
}

// Report returns atomscan's stored report for exact bytes, as it was uploaded.
// SQL never looks inside a report; a reader that wants one asks here.
func (st *Store) Report(ctx context.Context, sha256 []byte) ([]byte, error) {
	var packed []byte
	err := st.pool.QueryRow(ctx, `SELECT v.detail FROM samples s
		JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $2
		WHERE s.sha256 = $1 AND v.detail IS NOT NULL`, sha256, atomscan).Scan(&packed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: report: %w", err)
	}
	report, err := st.dec.DecodeAll(packed, nil)
	if err != nil {
		return nil, fmt.Errorf("store: report %x: %w", sha256, err)
	}
	return report, nil
}

// A scanned artifact's last confirmation is its scans row; a member has none,
// and its verdict's own stamp is when it was formed.
const recordColumns = `s.id, s.sha256, coalesce(n.name, ''), coalesce(s.version, ''),
	coalesce(v.class::text, ''), coalesce(sc.ruleset, v.ruleset, ''),
	CASE WHEN v.sample_id IS NOT NULL THEN coalesce(sc.scanned_at, v.formed_at) END,
	coalesce(sc.engine, ''), v.fires_at, v.summary`

// BySHA256 returns the record for exact bytes.
func (st *Store) BySHA256(ctx context.Context, sha256 []byte) (*Record, error) {
	return st.record(ctx, `SELECT `+recordColumns+`
		FROM samples s
		LEFT JOIN names n ON n.id = s.name_id
		LEFT JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $2
		LEFT JOIN scans sc ON sc.sample_id = s.id
		WHERE s.sha256 = $1`, sha256, atomscan)
}

// ByRelease returns the record for a package release. A release can hold
// several files; the one that fires at the tightest level is returned, then a
// clean one, then one with no level, newest scan first within each.
//
// With an empty version it returns the newest file of the name: the last
// one hopper learned of.
func (st *Store) ByRelease(ctx context.Context, name, version string) (*Record, error) {
	if name == "" {
		return nil, ErrNotFound
	}
	const query = `SELECT ` + recordColumns + `
		FROM names n
		JOIN samples s ON s.name_id = n.id
		JOIN verdicts v ON v.sample_id = s.id AND v.scanner_id = $2
		LEFT JOIN scans sc ON sc.sample_id = s.id
		WHERE n.name = $1 AND s.file_type IS DISTINCT FROM 'registry'`
	if version == "" {
		return st.record(ctx, query+` ORDER BY s.id DESC LIMIT 1`, name, atomscan) // samples_name, newest first
	}
	// A release holds a handful of files, so sorting them is cheaper than an
	// index that every rescan would have to maintain.
	return st.record(ctx, query+` AND s.version = $3
		ORDER BY (CASE WHEN v.fires_at > -1 THEN 0 WHEN v.fires_at = -1 THEN 1 ELSE 2 END),
		         (CASE WHEN v.fires_at > -1 THEN v.fires_at ELSE 0 END),
		         coalesce(sc.scanned_at, v.formed_at) DESC, s.sha256 LIMIT 1`, name, atomscan, version)
}

func (st *Store) record(ctx context.Context, query string, args ...any) (*Record, error) {
	var (
		r       Record
		scanned *time.Time
		engine  string
		raw     []byte
	)
	err := st.pool.QueryRow(ctx, query, args...).Scan(
		&r.ID, &r.SHA256, &r.Name, &r.Version, &r.Class, &r.Ruleset, &scanned, &engine, &r.FiresAt, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: lookup: %w", err)
	}
	if scanned == nil {
		return &r, nil // the bytes are known; nothing has scanned them
	}
	r.Analyzed, r.ScannedAt, r.Engine = true, scanned.UTC(), engine
	if len(raw) == 0 {
		return &r, nil
	}
	var s summary
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("store: sample %d: verdict summary: %w", r.ID, err)
	}
	r.Engine, r.Reason, r.Findings = cmp.Or(engine, s.Engine), s.Reason, s.Top
	return &r, nil
}
