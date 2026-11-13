// Command verdictproto loads hopper's legacy sample rows, staged in a local
// disposable database as legacy_samples, into the prototype verdict schema so
// both layouts can be measured over identical data. It is not part of hopper.
//
// The conversion is the interesting part:
//
//   - every report loses its placement (id, pid, path, depth, rel, via, role),
//     trait sources are rewritten from per-scan file ids to content hashes,
//     and the ruleset stamp moves to verdicts.ruleset, so the stored report is
//     a function of the bytes and the findings alone;
//   - archive members are attributed to their immediate container using pid,
//     not to the top-level archive;
//   - fetched dependencies become refs from the file that declared them;
//   - atomscan gets one verdict per sample, and its jurors (cleave, ml, llm)
//     get a row each, so a disagreement between them is a join.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/klauspost/compress/zstd"
)

const defaultDSN = "host=/tmp/hopper-schema-prototype/v2 port=5499 user=proto dbname=proto"

func main() {
	dsn := flag.String("dsn", defaultDSN, "local prototype database (Unix socket only)")
	flag.Parse()
	if err := run(context.Background(), *dsn); err != nil {
		slog.Error("verdictproto failed", "err", err)
		os.Exit(1)
	}
}

// Scanner ids, as schema.sql inserts them.
const (
	atomscan int16 = iota + 1
	cleaveJuror
	mlJuror
	llmJuror
)

// Classes, the one scale every scanner shares.
const (
	benign     = "benign"
	suspicious = "suspicious"
	hostile    = "hostile"
)

// placementKeys describe where a file sat in one scan, not what it is.
var placementKeys = []string{"id", "dp", "depth", "path", "pid", "rel", "via", "role"}

// stampKeys identify the scanner build or ruleset; they live in verdicts.ruleset.
// Containment and fetch state leave with "files" and "fetched".
var stampKeys = []string{"files", "fs", "fetched", "truncated", "omitted_files", "rev", "tv", "fp"}

var labels = map[string]bool{
	"unknown": true, "sighted": true, "good": true, "bad": true,
	"inconclusive": true, "dual-use": true, "purgatory": true,
}

// entry is the part of a report's file entry the loader reasons about.
type entry struct {
	ID    *int64 `json:"id"`
	PID   *int64 `json:"pid"`
	Depth *int   `json:"depth"`
	DP    *int   `json:"dp"`
	SHA   string `json:"sha"`
	Path  string `json:"path"`
	Rel   string `json:"rel"`
	Via   string `json:"via"`
	Type  string `json:"type"`
	Mol   string `json:"mol"`
	Refs  []struct {
		To   string `json:"to"`
		Kind string `json:"kind"`
	} `json:"refs"`
	Traits []struct {
		ID   string          `json:"id"`
		Dep  json.RawMessage `json:"dep,omitempty"`
		Crit int             `json:"crit"`
	} `json:"traits"`
	raw  json.RawMessage
	Size int64 `json:"size"`
	Risk int   `json:"risk"`
}

func (e *entry) depth() int {
	switch {
	case e.Depth != nil:
		return *e.Depth
	case e.DP != nil:
		return *e.DP
	default:
		return -1
	}
}

type fetched struct {
	Kind         string `json:"kind"`
	Locator      string `json:"locator"`
	SourceSHA256 string `json:"source_sha256"`
}

type edge struct{ parent, path, child string }

type ref struct {
	sample, name, version, kind string
}

type verdict struct {
	createdAt time.Time
	scanned   time.Time
	class     string // "" when the scanner reached no classification
	outcome   string
	ruleset   string
	digest    []byte
	detail    []byte
	summary   []byte
	sampleID  int64
	scanner   int16
}

type sample struct {
	createdAt   time.Time
	fetchedT    *time.Time
	labelSource *string
	name        *string
	version     *string
	url         *string
	publishedAt *time.Time
	fileType    string
	label       string
	sha         []byte
	provenance  []byte
	id          int64
	size        int64
}

// legacy is one row of today's samples table.
type legacy struct {
	analyzed, firstAnalyzed                  *time.Time
	provenance, cleave, litmus, llm          *string
	firesAt, mlClass                         *int32
	shaHex, path, parent, source, feed, skip string
	ruleset                                  string
	sample                                   sample
}

type location struct {
	seen     time.Time
	path     string
	source   string
	feed     string
	sampleID int64
}

// stats are reported at the end; each counter answers a question in PLAN.md.
type stats struct {
	rows, parents, fsFormat, truncated           int
	entries, withPID, byPrefix, rootFallback     int
	registryEdges, fetchedEntries, refsFromFetch int
	refsFromEntries, refsRejected                int
	unresolvedFrom, timeoutReports, stubs        int
	unresolvedInArchives, reportsUnresolved      int
	flatMulti, attributedMulti                   int
	stableShas, multiRulesetShas                 int
	detailRaw, detailZstd                        int64
}

// loader accumulates every output row in memory; the sample is small enough.
type loader struct {
	enc       *zstd.Encoder
	samples   map[string]*sample // by hex sha256
	edges     map[edge]bool
	refs      map[ref]bool
	locations map[string]location
	sizes     map[string]int64  // member sizes and types seen in parent reports,
	types     map[string]string // for samples the export did not include
	seenUnder map[string]map[string]string
	// scanIDs maps an archive's digest to the file ids of its stored scan, so a
	// member report citing a sibling by id can be resolved to the sibling's
	// digest. Ids are only meaningful within one scan.
	scanIDs  map[string]map[int64]string
	verdicts []verdict
	st       stats
	nextStub int64
}

func run(ctx context.Context, dsn string) error {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(cfg.Host, "/") || cfg.Database != "proto" {
		return fmt.Errorf("refusing %s/%s: only the local Unix-socket database proto", cfg.Host, cfg.Database)
	}
	read, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := read.Close(ctx); err != nil {
			slog.Warn("close connection", "err", err)
		}
	}()
	write, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := write.Close(ctx); err != nil {
			slog.Warn("close connection", "err", err)
		}
	}()
	for _, name := range []string{"label", "class", "outcome", "ref_kind"} {
		t, err := write.LoadType(ctx, name)
		if err != nil {
			return err
		}
		write.TypeMap().RegisterType(t)
	}

	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return err
	}
	l := &loader{
		enc: enc, samples: map[string]*sample{}, edges: map[edge]bool{}, refs: map[ref]bool{},
		locations: map[string]location{}, sizes: map[string]int64{}, types: map[string]string{},
		seenUnder: map[string]map[string]string{}, scanIDs: map[string]map[int64]string{},
	}
	start := time.Now()
	if err := l.indexScans(ctx, read); err != nil {
		return err
	}
	if err := l.read(ctx, read); err != nil {
		return err
	}
	slog.Info("read legacy rows", "rows", l.st.rows, "elapsed", time.Since(start).Round(time.Millisecond))
	if err := l.write(ctx, write); err != nil {
		return err
	}
	l.report()
	return nil
}

func (l *loader) indexScans(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `SELECT s.sha256, (f->>'id')::bigint, f->>'sha'
		FROM legacy_samples s, jsonb_array_elements(s.cleave_result->'files') f
		WHERE jsonb_array_length(s.cleave_result->'files') > 1 AND f ? 'id' AND f ? 'sha'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var parent, sha string
		var id int64
		if err := rows.Scan(&parent, &id, &sha); err != nil {
			return err
		}
		if l.scanIDs[parent] == nil {
			l.scanIDs[parent] = map[int64]string{}
		}
		l.scanIDs[parent][id] = sha
	}
	return rows.Err()
}

func (l *loader) read(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `SELECT id, sha256, size_bytes, coalesce(file_type, ''), label,
		nullif(label_source, ''), created_at, nullif(purl_base, ''), nullif(version, ''),
		nullif(url, ''), fetched_at, provenance::text, coalesce(path, ''), coalesce(parent, ''),
		coalesce(source, ''), coalesce(feed, ''), coalesce(skip, ''), coalesce(traits_version, ''),
		analyzed_at, first_analyzed_at, cleave_result::text, litmus_result::text, llm_result::text,
		lvl, litmus_class
		FROM legacy_samples ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var row legacy
		smp := &row.sample
		if err := rows.Scan(&smp.id, &row.shaHex, &smp.size, &smp.fileType, &smp.label, &smp.labelSource,
			&smp.createdAt, &smp.name, &smp.version, &smp.url, &smp.fetchedT, &row.provenance, &row.path,
			&row.parent, &row.source, &row.feed, &row.skip, &row.ruleset, &row.analyzed, &row.firstAnalyzed,
			&row.cleave, &row.litmus, &row.llm, &row.firesAt, &row.mlClass); err != nil {
			return err
		}
		l.st.rows++
		if smp.sha, err = hex.DecodeString(row.shaHex); err != nil || len(smp.sha) != 32 {
			return fmt.Errorf("sample %d: bad sha256 %q", smp.id, row.shaHex)
		}
		if !labels[smp.label] {
			return fmt.Errorf("sample %d: unknown label %q", smp.id, smp.label)
		}
		if row.provenance != nil {
			smp.provenance = []byte(*row.provenance)
			smp.publishedAt = publishedAt(smp.provenance)
		}
		l.samples[row.shaHex] = smp
		l.nextStub = max(l.nextStub, smp.id+1)
		if _, dup := l.locations[row.path]; row.parent == "" && row.path != "" && !dup {
			l.locations[row.path] = location{
				path: row.path, source: row.source, feed: row.feed, sampleID: smp.id, seen: smp.createdAt,
			}
		}
		if err := l.judge(&row); err != nil {
			return fmt.Errorf("sample %d: %w", smp.id, err)
		}
	}
	return rows.Err()
}

// judge records atomscan's verdict on one legacy row and a row for each juror
// that ran. atomscan's own verdict is what /v1/lookup serves: the blended
// class, the level it fires at, the reason, and the strongest findings. The
// export holds no separate blend, so the served ML class stands in.
func (l *loader) judge(row *legacy) error {
	if row.cleave == nil && row.litmus == nil {
		return nil
	}
	id := row.sample.id
	scanned := row.sample.createdAt
	if row.analyzed != nil {
		scanned = *row.analyzed
	}
	created := scanned
	if row.firstAnalyzed != nil {
		created = *row.firstAnalyzed
	}
	scan := verdict{sampleID: id, scanner: atomscan, outcome: "ok", createdAt: created, scanned: scanned}
	served := map[string]any{}
	if row.cleave != nil {
		v, err := l.cleave(id, row.shaHex, row.parent, *row.cleave, row.ruleset)
		if err != nil {
			return err
		}
		if row.skip == "unsupported" || row.skip == "timeout" {
			v.outcome, v.class = row.skip, ""
			scan.outcome = row.skip
		}
		v.createdAt, v.scanned = created, scanned
		l.verdicts = append(l.verdicts, v)
		scan.ruleset = row.ruleset
		var own struct {
			Top json.RawMessage `json:"top"`
		}
		if json.Unmarshal(v.summary, &own) == nil && own.Top != nil {
			served["top"] = own.Top
		}
	}
	var envelopeReason string
	if row.litmus != nil {
		// The newest results nest the ML record beside the interpreter's
		// sentence; older ones are the ML record alone.
		report := *row.litmus
		var envelope struct {
			LLM struct {
				Interpretation string `json:"interpretation"`
			} `json:"llm"`
			ML json.RawMessage `json:"ml"`
		}
		if json.Unmarshal([]byte(report), &envelope) == nil && len(envelope.ML) > 0 && envelope.ML[0] == '{' {
			report, envelopeReason = string(envelope.ML), envelope.LLM.Interpretation
		}
		v, eng, err := l.ml(id, report, row.mlClass, row.firesAt, created, scanned)
		if err != nil {
			return fmt.Errorf("litmus: %w", err)
		}
		l.verdicts = append(l.verdicts, v)
		scan.class, scan.scanned = v.class, v.scanned
		if row.firesAt != nil {
			served["fires_at"] = *row.firesAt
		}
		if eng != "" {
			served["eng"] = eng
		}
	}
	if row.llm != nil {
		v, reason, err := l.llm(id, *row.llm, created, scanned)
		if err != nil {
			return fmt.Errorf("llm: %w", err)
		}
		l.verdicts = append(l.verdicts, v)
		if reason != "" {
			served["reason"] = reason
		}
	}
	if envelopeReason != "" {
		served["reason"] = envelopeReason
	}
	if scan.outcome != "ok" {
		scan.class = ""
	}
	summary, err := json.Marshal(served)
	if err != nil {
		return err
	}
	scan.summary = summary
	l.verdicts = append(l.verdicts, scan)
	return nil
}

// cleave converts one cleave report: its verdict row, and — for archives — the
// member edges and references it carries.
func (l *loader) cleave(id int64, shaHex, parent, report, ruleset string) (verdict, error) {
	top, err := decodeObject([]byte(report))
	if err != nil {
		return verdict{}, err
	}
	result := verdict{sampleID: id, scanner: cleaveJuror, outcome: "ok", class: benign, ruleset: ruleset}
	if _, old := top["fs"]; old {
		// v4/v5 used single-letter keys and no member identities; keep the
		// report whole rather than guess at its placement fields.
		l.st.fsFormat++
		for _, k := range []string{"tv", "rev"} {
			delete(top, k)
		}
		return l.finish(result, top, true)
	}
	var files []json.RawMessage
	if raw, ok := top["files"]; ok {
		if err := json.Unmarshal(raw, &files); err != nil {
			return verdict{}, fmt.Errorf("files: %w", err)
		}
	}
	entries := make([]*entry, 0, len(files))
	for i, raw := range files {
		e := &entry{raw: raw}
		if err := json.Unmarshal(raw, e); err != nil {
			return verdict{}, fmt.Errorf("files[%d]: %w", i, err)
		}
		entries = append(entries, e)
	}
	root := rootEntry(entries)
	if root == nil {
		return l.finish(result, top, true)
	}
	if strings.Contains(report, "Rule evaluation timeout") {
		l.st.timeoutReports++ // the finding text carries a wall-clock duration
	}

	byID := make(map[int64]*entry, len(entries))
	for _, e := range entries {
		if e.ID != nil {
			byID[*e.ID] = e
		}
	}
	if len(entries) > 1 {
		l.archive(shaHex, ruleset, top, root, entries, byID)
	}
	for _, e := range entries {
		for _, r := range e.Refs {
			if r.Kind == "dependency" && l.addRef(e.SHA, r.To, "dependency") {
				l.st.refsFromEntries++
			}
		}
	}

	// A member's report may cite files of the archive scan it came from; use
	// that scan's ids only if it is the scan this report was cut from.
	scan := l.scanIDs[parent]
	if root.ID == nil || scan[*root.ID] != root.SHA {
		scan = nil
	}
	resolve := func(fid int64) string {
		if e := byID[fid]; e != nil {
			return e.SHA
		}
		return scan[fid]
	}
	before := l.st.unresolvedFrom
	file, err := placementFree(root, resolve, &l.st.unresolvedFrom)
	if n := l.st.unresolvedFrom - before; n > 0 {
		if len(entries) > 1 {
			l.st.unresolvedInArchives += n
		}
		l.st.reportsUnresolved++
	}
	if err != nil {
		return verdict{}, err
	}
	for _, k := range stampKeys {
		delete(top, k)
	}
	top["file"] = file

	// Stand-in for scan's trait floor, using hopper's conviction bar: one
	// hostile finding or two suspicious ones convict; one suspicious is a flag.
	worst, flagged := 0, 0
	var strong []map[string]any
	for _, t := range root.Traits {
		worst = max(worst, t.Crit)
		if t.Crit >= 4 {
			flagged++
		}
	}
	for c := 5; c >= 4 && len(strong) < 3; c-- { // mirrors encodeTopTraits
		for _, t := range root.Traits {
			if t.Crit == c && t.ID != "" && len(strong) < 3 {
				m := map[string]any{"id": t.ID, "crit": t.Crit}
				if len(t.Dep) > 0 && string(t.Dep) != "null" {
					m["dep"] = t.Dep
				}
				strong = append(strong, m)
			}
		}
	}
	switch {
	case worst >= 5 || flagged >= 2:
		result.class = hostile
	case worst == 4:
		result.class = suspicious
	default:
		result.class = benign
	}
	summary := map[string]any{"crit": worst, "n": flagged}
	if len(strong) > 0 {
		summary["top"] = strong
	}
	if result.summary, err = json.Marshal(summary); err != nil {
		return verdict{}, err
	}
	return l.finish(result, top, true)
}

// archive records containment edges and dependency references. A member's
// container is its pid entry; old reports without pid fall back to the longest
// enclosing path. A fetched entry is a dependency, not something inside the
// declaring file, so it becomes a ref; its own contents hang off it by pid.
func (l *loader) archive(shaHex, ruleset string, top map[string]json.RawMessage, root *entry, entries []*entry, byID map[int64]*entry) {
	l.st.parents++
	if _, ok := top["truncated"]; ok {
		l.st.truncated++
	}
	byPath := make(map[string]*entry, len(entries))
	for _, e := range entries {
		byPath[e.Path] = e
	}
	flat := map[string]map[string]bool{} // today's attribution: top-level archive + last segment
	attributed := map[[2]string]map[string]bool{}
	for _, e := range entries {
		if e == root || e.SHA == "" {
			continue
		}
		l.st.entries++
		l.sizes[e.SHA] = e.Size
		l.types[e.SHA] = e.Type
		if l.seenUnder[e.SHA] == nil {
			l.seenUnder[e.SHA] = map[string]string{}
		}
		l.seenUnder[e.SHA][ruleset] = fmt.Sprintf("%d/%s", e.Risk, e.Mol)

		last := e.Path
		if i := strings.LastIndex(last, "!!"); i >= 0 {
			last = last[i+2:]
		}
		if flat[last] == nil {
			flat[last] = map[string]bool{}
		}
		flat[last][e.SHA] = true

		switch {
		case e.Rel == "registry", e.Type == "registry": // older reports lack rel
			l.st.registryEdges++ // registry metadata, provenance of a release
			continue
		case e.Rel == "fetched":
			l.st.fetchedEntries++
			if p := byID[ptr(e.PID)]; e.PID != nil && p != nil {
				l.addRef(p.SHA, e.Path, "dependency")
			}
			continue
		default: // contained in its parent's bytes
		}

		var p *entry
		switch {
		case e.PID != nil && byID[*e.PID] != nil:
			p = byID[*e.PID]
			l.st.withPID++
		default:
			for i := strings.LastIndex(e.Path, "!!"); i > 0 && p == nil; i = strings.LastIndex(e.Path[:i], "!!") {
				p = byPath[e.Path[:i]]
			}
			if p != nil {
				l.st.byPrefix++
			} else {
				p = root
				l.st.rootFallback++
			}
		}
		parentSHA := p.SHA
		if p == root {
			parentSHA = shaHex
		}
		rel, ok := strings.CutPrefix(e.Path, p.Path+"!!")
		if !ok {
			rel = last
		}
		l.edges[edge{parent: parentSHA, path: rel, child: e.SHA}] = true
		k := [2]string{parentSHA, rel}
		if attributed[k] == nil {
			attributed[k] = map[string]bool{}
		}
		attributed[k][e.SHA] = true
	}
	for _, kids := range flat {
		if len(kids) > 1 {
			l.st.flatMulti++
		}
	}
	for _, kids := range attributed {
		if len(kids) > 1 {
			l.st.attributedMulti++
		}
	}

	var list []fetched
	if raw, ok := top["fetched"]; ok && json.Unmarshal(raw, &list) == nil {
		for _, f := range list {
			kind := f.Kind
			if kind != "dependency" && kind != "command" && kind != "url_fetch" {
				l.st.refsRejected++
				continue
			}
			if l.addRef(f.SourceSHA256, f.Locator, kind) {
				l.st.refsFromFetch++
			}
		}
	}
}

// addRef records that the file with digest sample names locator. It reports
// whether the reference was usable: a PURL or an http(s) URL.
func (l *loader) addRef(sample, locator, kind string) bool {
	if len(sample) != 64 {
		l.st.refsRejected++
		return false
	}
	name, version := splitLocator(locator)
	if name == "" {
		l.st.refsRejected++
		return false
	}
	l.refs[ref{sample: sample, name: name, version: version, kind: kind}] = true
	return true
}

// splitLocator separates a PURL's version from its name, dropping qualifiers
// and subpath. A URL is a name with no version.
func splitLocator(loc string) (name, version string) {
	switch {
	case strings.HasPrefix(loc, "https://"), strings.HasPrefix(loc, "http://"):
		return loc, ""
	case !strings.HasPrefix(loc, "pkg:"):
		return "", ""
	}
	if i := strings.IndexAny(loc, "?#"); i >= 0 {
		loc = loc[:i]
	}
	if at := strings.LastIndexByte(loc, '@'); at > strings.LastIndexByte(loc, '/') {
		return loc[:at], loc[at+1:]
	}
	return loc, ""
}

// ml converts the ML ensemble's result and returns the scan build that produced
// it. Its per-file list is dropped: those are the members' own verdicts. What
// remains fits in summary for all but a few.
func (l *loader) ml(id int64, report string, class, firesAt *int32, created, scanned time.Time) (verdict, string, error) {
	top, err := decodeObject([]byte(report))
	if err != nil {
		return verdict{}, "", err
	}
	var eng string
	if raw, ok := top["eng"]; ok && json.Unmarshal(raw, &eng) != nil {
		eng = ""
	}
	v := verdict{sampleID: id, scanner: mlJuror, outcome: "ok", createdAt: created, scanned: scanned}
	if at, ok := top["analyzed_at"]; ok {
		var s string
		if json.Unmarshal(at, &s) == nil {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				v.scanned = t
			}
		}
	}
	switch {
	case class != nil && *class >= 0 && *class <= 2:
		v.class = []string{benign, suspicious, hostile}[*class]
	case firesAt != nil && *firesAt == -1:
		v.class = benign
	default: // scored before classes existed
	}
	v.ruleset = strings.Trim(string(top["version"])+" "+string(top["eng"]), `" `)
	summary := map[string]json.RawMessage{}
	for _, k := range []string{"lvl", "prob", "conf"} {
		if x, ok := top[k]; ok {
			summary[k] = x
		}
	}
	if v.summary, err = json.Marshal(summary); err != nil {
		return verdict{}, "", err
	}
	for _, k := range []string{"analyzed_at", "version", "eng", "files", "id"} {
		delete(top, k)
	}
	v, err = l.finish(v, top, false)
	return v, eng, err
}

// llm converts the interpreter's result and returns its one-sentence reason.
func (l *loader) llm(id int64, report string, created, scanned time.Time) (verdict, string, error) {
	top, err := decodeObject([]byte(report))
	if err != nil {
		return verdict{}, "", err
	}
	var r struct{ Grade, Model, Error, Interpretation string }
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		return verdict{}, "", err
	}
	v := verdict{sampleID: id, scanner: llmJuror, outcome: "ok", ruleset: r.Model, createdAt: created, scanned: scanned}
	switch r.Grade {
	case benign, suspicious, hostile:
		v.class = r.Grade
	case "malicious":
		v.class = hostile
	default: // no grade: the model declined or failed
	}
	if r.Error != "" {
		v.outcome, v.class = "error", ""
	}
	summary := map[string]json.RawMessage{}
	for _, k := range []string{"grade", "conf", "interpretation"} {
		if x, ok := top[k]; ok {
			summary[k] = x
		}
	}
	if v.summary, err = json.Marshal(summary); err != nil {
		return verdict{}, "", err
	}
	delete(top, "model")
	v, err = l.finish(v, top, false)
	return v, r.Interpretation, err
}

// finish canonicalizes the report (sorted keys, exact numbers) and digests it:
// equal findings on equal bytes yield equal digests. The compressed report is
// kept when always is set or it would not fit in a summary.
func (l *loader) finish(v verdict, report map[string]json.RawMessage, always bool) (verdict, error) {
	canon, err := json.Marshal(report)
	if err != nil {
		return verdict{}, err
	}
	sum := sha256.Sum256(canon)
	v.digest = sum[:]
	if always || len(canon) > 1024 {
		v.detail = l.enc.EncodeAll(canon, nil)
		l.st.detailRaw += int64(len(canon))
		l.st.detailZstd += int64(len(v.detail))
	}
	return v, nil
}

// placementFree strips placement from a file entry and rewrites trait and
// reference sources from scan-local file ids to content digests; a source that
// is the entry itself loses its file key.
func placementFree(e *entry, resolve func(int64) string, unresolved *int) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(e.raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	for _, k := range placementKeys {
		delete(m, k)
	}
	rewrite := func(src map[string]any) {
		n, ok := src["file"].(json.Number)
		if !ok {
			return
		}
		fid, err := n.Int64()
		switch {
		case err != nil:
			*unresolved++
		case e.ID != nil && fid == *e.ID:
			delete(src, "file")
		case resolve(fid) != "":
			delete(src, "file")
			src["sha"] = resolve(fid)
		default:
			*unresolved++
		}
	}
	for _, t := range asMaps(m["traits"]) {
		for _, src := range asMaps(t["from"]) {
			rewrite(src)
		}
	}
	for _, r := range asMaps(m["refs"]) {
		rewrite(r)
	}
	return json.Marshal(m)
}

func asMaps(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// rootEntry is the depth-0 entry: the file the report describes.
func rootEntry(entries []*entry) *entry {
	for _, e := range entries {
		if e.depth() == 0 {
			return e
		}
	}
	if len(entries) > 0 {
		return entries[0]
	}
	return nil
}

func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("report is not a JSON object")
	}
	return m, nil
}

func publishedAt(provenance []byte) *time.Time {
	var p struct {
		Registry struct {
			Record struct {
				PublishedAt *int64 `json:"published_at"`
			} `json:"record"`
		} `json:"registry"`
	}
	if json.Unmarshal(provenance, &p) != nil || p.Registry.Record.PublishedAt == nil {
		return nil
	}
	t := time.Unix(*p.Registry.Record.PublishedAt, 0).UTC()
	return &t
}

func ptr(p *int64) int64 {
	if p == nil {
		return -1
	}
	return *p
}

// sampleID returns the id for a digest, creating a stub sample for files the
// export did not include (members of truncated or unexported archives).
func (l *loader) sampleID(shaHex string) (int64, error) {
	if s, ok := l.samples[shaHex]; ok {
		return s.id, nil
	}
	b, err := hex.DecodeString(shaHex)
	if err != nil || len(b) != 32 {
		return 0, fmt.Errorf("bad sha256 %q", shaHex)
	}
	s := &sample{
		id: l.nextStub, sha: b, size: l.sizes[shaHex], fileType: l.types[shaHex],
		label: "unknown", createdAt: time.Now().UTC(),
	}
	l.nextStub++
	l.st.stubs++
	l.samples[shaHex] = s
	return s.id, nil
}

func (l *loader) write(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(ctx, `TRUNCATE names, samples, verdicts, verdict_details, contents,
		refs, locations, queue`); err != nil {
		return err
	}

	// Resolve every digest an edge or ref mentions before samples are copied.
	// One contents row per archive, members in path order.
	type listing struct {
		children []int64
		paths    []string
	}
	contents := map[int64]*listing{}
	for _, e := range slices.SortedFunc(maps.Keys(l.edges), func(a, b edge) int {
		return cmp.Or(strings.Compare(a.parent, b.parent), strings.Compare(a.path, b.path), strings.Compare(a.child, b.child))
	}) {
		p, err := l.sampleID(e.parent)
		if err != nil {
			return err
		}
		c, err := l.sampleID(e.child)
		if err != nil {
			return err
		}
		ls := contents[p]
		if ls == nil {
			ls = &listing{}
			contents[p] = ls
		}
		ls.children = append(ls.children, c)
		ls.paths = append(ls.paths, e.path)
	}
	names := map[string]int64{}
	nameID := func(n string) int64 {
		id, ok := names[n]
		if !ok {
			id = int64(len(names) + 1)
			names[n] = id
		}
		return id
	}
	var refRows [][]any
	for r := range l.refs {
		sid, err := l.sampleID(r.sample)
		if err != nil {
			return err
		}
		refRows = append(refRows, []any{sid, nameID(r.name), r.version, r.kind})
	}
	var sampleRows [][]any
	for _, s := range l.samples {
		var nid *int64
		if s.name != nil {
			id := nameID(*s.name)
			nid = &id
		}
		sampleRows = append(sampleRows, []any{
			s.id, s.sha, s.size, nullable(s.fileType), s.label,
			s.labelSource, s.createdAt, nid, s.version, s.publishedAt, s.url, s.fetchedT, jsonb(s.provenance),
		})
	}

	var nameRows [][]any
	for n, id := range names {
		nameRows = append(nameRows, []any{id, n})
	}
	var verdictRows, detailRows [][]any
	for i := range l.verdicts {
		v := &l.verdicts[i]
		verdictRows = append(verdictRows, []any{
			v.sampleID, v.scanner, v.outcome, nullable(v.class),
			v.ruleset, v.createdAt, v.scanned, v.digest, jsonb(v.summary),
		})
		if v.detail != nil {
			detailRows = append(detailRows, []any{v.sampleID, v.scanner, v.detail})
		}
	}
	var contentRows, locationRows [][]any
	for p, ls := range contents {
		contentRows = append(contentRows, []any{p, ls.children, ls.paths})
	}
	for _, loc := range l.locations {
		locationRows = append(locationRows, []any{
			loc.path, loc.sampleID, nullable(loc.source),
			nullable(loc.feed), nil, loc.seen,
		})
	}

	for _, c := range []struct {
		table string
		cols  []string
		rows  [][]any
	}{
		{"names", []string{"id", "name"}, nameRows},
		{"samples", []string{
			"id", "sha256", "size_bytes", "file_type", "label", "label_source", "created_at",
			"name_id", "version", "published_at", "url", "fetched_at", "provenance",
		}, sampleRows},
		{"verdicts", []string{
			"sample_id", "scanner_id", "outcome", "class", "ruleset", "created_at",
			"scanned_at", "digest", "summary",
		}, verdictRows},
		{"verdict_details", []string{"sample_id", "scanner_id", "detail"}, detailRows},
		{"contents", []string{"parent_id", "child_ids", "paths"}, contentRows},
		{"refs", []string{"sample_id", "name_id", "version", "kind"}, refRows},
		{"locations", []string{"path", "sample_id", "source", "feed", "mtime", "seen_at"}, locationRows},
	} {
		start := time.Now()
		n, err := tx.CopyFrom(ctx, pgx.Identifier{c.table}, c.cols, pgx.CopyFromRows(c.rows))
		if err != nil {
			return fmt.Errorf("copy %s: %w", c.table, err)
		}
		slog.Info("copied", "table", c.table, "rows", n, "elapsed", time.Since(start).Round(time.Millisecond))
	}
	for _, seq := range []string{"names", "samples"} {
		if _, err := tx.Exec(ctx, fmt.Sprintf(
			`SELECT setval(pg_get_serial_sequence('%[1]s', 'id'), (SELECT max(id) FROM %[1]s))`, seq)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (l *loader) report() {
	for _, under := range l.seenUnder {
		if len(under) < 2 {
			continue
		}
		l.st.multiRulesetShas++
		vals := slices.Collect(maps.Values(under))
		if !slices.ContainsFunc(vals, func(s string) bool { return s != vals[0] }) {
			l.st.stableShas++
		}
	}
	s := l.st
	slog.Info("reports",
		"rows", s.rows, "archives", s.parents, "fs_format", s.fsFormat, "truncated", s.truncated,
		"timeout_findings", s.timeoutReports, "unresolved_trait_sources", s.unresolvedFrom,
		"unresolved_in_archive_reports", s.unresolvedInArchives, "reports_with_unresolved", s.reportsUnresolved,
		"detail_raw_bytes", s.detailRaw, "detail_zstd_bytes", s.detailZstd)
	slog.Info("members",
		"entries", s.entries, "by_pid", s.withPID, "by_path_prefix", s.byPrefix, "root_fallback", s.rootFallback,
		"registry_sidecars_skipped", s.registryEdges, "fetched_entries_as_refs", s.fetchedEntries,
		"edges", len(l.edges), "stub_samples", s.stubs,
		"multi_child_paths_flattened", s.flatMulti, "multi_child_paths_attributed", s.attributedMulti)
	slog.Info("refs", "refs", len(l.refs), "from_fetched", s.refsFromFetch,
		"from_entries", s.refsFromEntries, "rejected", s.refsRejected)
	slog.Info("stability across rulesets (parent ref risk+formula)",
		"member_shas_seen_under_2plus_rulesets", s.multiRulesetShas, "identical", s.stableShas,
		"pct", strconv.FormatFloat(100*float64(s.stableShas)/float64(max(1, s.multiRulesetShas)), 'f', 1, 64))
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func jsonb(b []byte) any {
	if b == nil {
		return nil
	}
	return json.RawMessage(b)
}
