// Package v7result converts a version 7 result ({sha256, worker, ml, llm,
// raw}) into the version 8 files of package scanresult.
//
// Hopper uses it for workers that still upload version 7. Readers of results
// stored before version 8 (hopper's samples hold the raw, ml and llm blobs
// as they arrived) use it to read old and new results the same way. It
// stores nothing and needs no database.
//
// Each file's report is rebuilt in the version 8 shape, as scan builds it: the
// file's own entry, with nothing that says where it sat and every source in
// another file cited by its sha256. Members and references move out of the
// report into contents and refs. Reports older than version 6 use another
// schema and are left out; their verdicts and jurors are still converted.
// Version 7 does not separate the trait floor from the model, so the floor
// juror here is a stand-in computed from the file's own findings with hopper's
// conviction bar: one finding at crit 5 or two at crit 4 convict.
package v7result

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atomdrift-project/hopper/scanresult"
)

// Result is a version 7 result as hopper's /v1/work/result decodes it.
type Result struct {
	// At is when hopper received the result; the ML section's own time wins.
	At     time.Time
	SHA256 string
	Worker string
	// Ruleset is the traits version the worker reported; the report's wins.
	Ruleset string
	ML      json.RawMessage
	LLM     json.RawMessage
	Raw     json.RawMessage
}

// Version 7 sends a level, not a class (except when the interpreter placed
// the level). The class is derived here exactly as scan derives it, and as
// gauntlet's ascanTier documents: at deploy level n, a file firing at or below
// n is hostile; one firing at or below min(25000, max(500, 100n)) is
// suspicious, as are the trait floor's former off-grid markers (grid maximum
// plus 1 or 2); -1 and anything looser are benign. Version 8 sends the class.
const (
	gridMax          = 25000
	suspiciousFloor  = 500
	suspiciousFactor = 100
)

// Converted is a version 7 result as version 8 files.
type Converted struct {
	// Omitted counts what was left out and why, for the caller to log.
	Omitted map[string]int
	Files   []scanresult.File
}

// The interpreter's text is the worker's to send at any length; these bound
// what of it a verdict carries, so that the verdict stays within
// scanresult.MaxSummary.
const (
	maxReason = 400
	maxError  = 200
	maxModel  = 100
)

// clip is s as a verdict can hold it: UTF-8 without NULs, at most n bytes,
// cut at a character boundary.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// entry is the part of a report's file entry the conversion reads.
type entry struct {
	ID    *int64 `json:"id"`
	PID   *int64 `json:"pid"`
	Depth *int   `json:"depth"`
	DP    *int   `json:"dp"`
	SHA   string `json:"sha"`
	Path  string `json:"path"`
	Rel   string `json:"rel"`
	Type  string `json:"type"`
	Refs  []struct {
		To   string `json:"to"`
		Kind string `json:"kind"`
	} `json:"refs"`
	Traits []trait `json:"traits"`
	// Ident is the file's identity block. It moves to the file line.
	Ident json.RawMessage `json:"ident"`
	raw   json.RawMessage
	Size  int64 `json:"size"`
}

// placement is what a version 8 report never carries: sha, size, type and
// ident are on the file line, and the rest say where the file sat, which would
// make the same bytes report differently from every archive that holds them.
// It is PLACEMENT_KEYS in scan's src/engine/v8.rs.
var placement = []string{"id", "pid", "depth", "dp", "path", "rel", "via", "role", "sha", "size", "type", "ident"}

type trait struct {
	ID string `json:"id"`
	// Dep is set on a dependency's verdict pinned onto the file. It is about
	// another artifact, so it is not one of the file's findings.
	Dep  json.RawMessage `json:"dep"`
	Crit int             `json:"crit"`
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

// ml is the ML section in any of the shapes stored or sent since levels
// existed: flat, nested beside the interpreter as {ml, llm}, with the level
// under "lvl" or (version 6) "l", and members under "files" or "fs".
type ml struct {
	Nested     json.RawMessage `json:"ml"`
	LLM        json.RawMessage `json:"llm"`
	Lvl        json.RawMessage `json:"lvl"`
	L          json.RawMessage `json:"l"`
	Cls        json.RawMessage `json:"cls"`
	Class      json.RawMessage `json:"class"`
	Prob       *float64        `json:"prob"`
	Version    string          `json:"version"`
	Eng        string          `json:"eng"`
	AnalyzedAt string          `json:"analyzed_at"`
	Files      []mlFile        `json:"files"`
	FS         []mlFile        `json:"fs"`
}

type mlFile struct {
	ID      *int64   `json:"id"`
	Prob    *float64 `json:"prob"`
	Verdict *struct {
		Prob *float64        `json:"prob"`
		Lvl  json.RawMessage `json:"lvl"`
	} `json:"verdict"`
	Lvl json.RawMessage `json:"lvl"`
	L   json.RawMessage `json:"l"`
}

// llm is the interpreter's section: a grade, or a failure.
type llm struct {
	Before *struct {
		Prob *float64        `json:"prob"`
		Lvl  json.RawMessage `json:"lvl"`
	} `json:"before"`
	Conf           *float64 `json:"conf"`
	Grade          string   `json:"grade"`
	Interpretation string   `json:"interpretation"`
	Model          string   `json:"model"`
	Error          string   `json:"error"`
	Inject         bool     `json:"inject"`
}

// opinion is a verdict or juror object as version 8 spells it.
type opinion struct {
	FiresAt *int                 `json:"fires_at,omitempty"`
	Prob    *float64             `json:"prob,omitempty"`
	Conf    *float64             `json:"conf,omitempty"`
	Outcome string               `json:"outcome,omitempty"`
	Error   string               `json:"error,omitempty"`
	Class   string               `json:"class,omitempty"`
	Model   string               `json:"model,omitempty"`
	Reason  string               `json:"reason,omitempty"`
	Top     []scanresult.Finding `json:"top,omitempty"`
	// Hostile and Suspicious count the crit 5 and crit 4 findings, as scan's
	// floor juror does (FloorObject in src/engine/v8.rs).
	Hostile    int  `json:"hostile,omitempty"`
	Suspicious int  `json:"suspicious,omitempty"`
	Inject     bool `json:"inject,omitempty"`
}

// converter carries one conversion.
type converter struct {
	out     *Converted
	index   map[string]int   // file index by hex digest
	shas    map[int64]string // hex digest by the report's file id
	members map[int][]member
	level   int // the deploy level classes are graded at
}

type member struct {
	path  string
	child int
}

// Convert turns a version 7 result into version 8 files. A result
// that reports an error carries no analysis and is the caller's to record.
func Convert(r *Result, level int) (*Converted, error) {
	top := map[string]json.RawMessage{}
	if err := json.Unmarshal(r.Raw, &top); err != nil {
		return nil, fmt.Errorf("v7result: raw: %w", err)
	}
	var sec ml
	if len(r.ML) > 0 {
		if err := json.Unmarshal(r.ML, &sec); err != nil {
			return nil, fmt.Errorf("v7result: ml: %w", err)
		}
	}
	interp := r.LLM
	if len(sec.Nested) > 0 && sec.Nested[0] == '{' { // the stored {ml, llm} envelope
		if len(interp) == 0 {
			interp = sec.LLM
		}
		sec = ml{}
		if err := json.Unmarshal(r.ML, &struct {
			ML *ml `json:"ml"`
		}{&sec}); err != nil {
			return nil, fmt.Errorf("v7result: ml: %w", err)
		}
	}
	var in llm
	if len(interp) > 0 && string(interp) != "null" {
		if err := json.Unmarshal(interp, &in); err != nil {
			return nil, fmt.Errorf("v7result: llm: %w", err)
		}
	}

	scan := scanresult.Stamp{At: r.At.UTC(), Engine: sec.Eng, Ruleset: r.Ruleset, Worker: r.Worker, Level: level}
	if t, err := time.Parse(time.RFC3339, sec.AnalyzedAt); err == nil {
		scan.At = t.UTC()
	}
	for _, key := range []string{"rev", "tv"} {
		var rev string
		if json.Unmarshal(top[key], &rev) == nil && rev != "" {
			scan.Ruleset = rev
			break
		}
	}

	c := &converter{
		out:   &Converted{Omitted: map[string]int{}},
		index: map[string]int{}, members: map[int][]member{}, level: level,
	}
	entries, err := decodeEntries(top)
	if err != nil {
		return nil, err
	}
	root := rootEntry(entries)
	if root == nil {
		// v4/v5 reports use single-letter keys and carry no member
		// identities: keep the report whole and judge the file alone.
		if _, err := c.file(r.SHA256, 0, ""); err != nil {
			return nil, err
		}
		c.out.Omitted["report older than version 6"]++
		c.judge(0, &sec, nil, &in, nil, nil)
		return c.finish(scan)
	}
	if root.SHA != r.SHA256 {
		return nil, fmt.Errorf("v7result: report describes %q, result is for %q", root.SHA, r.SHA256)
	}
	if _, err := c.file(root.SHA, root.Size, root.Type); err != nil {
		return nil, err
	}
	c.claim(0, root)
	if root.Type == "" {
		// cleave could not classify the file: there is nothing to judge.
		c.out.Files[0].Verdict = json.RawMessage(`{"outcome":"unsupported"}`)
		return c.finish(scan)
	}
	c.shas = make(map[int64]string, len(entries))
	for _, e := range entries {
		if e.ID != nil {
			c.shas[*e.ID] = e.SHA
		}
	}
	rootReport, err := c.report(root)
	if err != nil {
		return nil, err
	}
	byID := map[int64]*mlFile{}
	for i := range sec.files() {
		if f := &sec.files()[i]; f.ID != nil {
			byID[*f.ID] = f
		}
	}
	c.judge(0, &sec, nil, &in, root.Traits, rootReport)
	if err := c.archive(root, entries, &sec, byID); err != nil {
		return nil, err
	}
	if err := c.refs(top, entries); err != nil {
		return nil, err
	}
	return c.finish(scan)
}

func decodeEntries(top map[string]json.RawMessage) ([]*entry, error) {
	raw, ok := top["files"]
	if !ok {
		return nil, nil
	}
	var files []json.RawMessage
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, fmt.Errorf("v7result: files: %w", err)
	}
	entries := make([]*entry, 0, len(files))
	for i, f := range files {
		e := &entry{raw: f}
		if err := json.Unmarshal(f, e); err != nil {
			return nil, fmt.Errorf("v7result: files[%d]: %w", i, err)
		}
		e.Traits = slices.DeleteFunc(e.Traits, func(t trait) bool { return t.Dep != nil })
		entries = append(entries, e)
	}
	return entries, nil
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

// file returns the index of the file with this digest, adding it if new.
func (c *converter) file(hexed string, size int64, fileType string) (int, error) {
	if i, ok := c.index[hexed]; ok {
		return i, nil
	}
	sha, err := hex.DecodeString(hexed)
	if err != nil || len(sha) != 32 {
		return 0, fmt.Errorf("v7result: %q is not a sha256", hexed)
	}
	c.index[hexed] = len(c.out.Files)
	c.out.Files = append(c.out.Files, scanresult.File{SHA256: sha, Size: size, Type: fileType})
	return len(c.out.Files) - 1, nil
}

// archive adds every file inside the archive and attributes each to its
// immediate container: its pid entry, else the longest enclosing path, else
// the archive itself. Registry sidecars are provenance and are left out; a
// fetched dependency is its own file, referenced rather than contained, and
// its contents hang off it.
func (c *converter) archive(root *entry, entries []*entry, m *ml, byID map[int64]*mlFile) error {
	ids := make(map[int64]*entry, len(entries))
	paths := make(map[string]*entry, len(entries))
	for _, e := range entries {
		if e.ID != nil {
			ids[*e.ID] = e
		}
		paths[e.Path] = e
	}
	files := m.files()
	for _, e := range entries {
		switch {
		case e == root:
			continue
		case e.Rel == "registry", e.Type == "registry": // older reports lack rel
			c.out.Omitted["registry sidecar"]++
			continue
		case len(e.SHA) != 64:
			c.out.Omitted["member without a digest"]++
			continue
		default:
		}
		i, err := c.file(e.SHA, e.Size, e.Type)
		if err != nil {
			return err
		}
		c.claim(i, e)
		if c.out.Files[i].Verdict == nil {
			mf := (*mlFile)(nil)
			if e.ID != nil {
				mf = byID[*e.ID]
				if mf == nil && *e.ID >= 0 && *e.ID < int64(len(files)) {
					mf = &files[*e.ID]
				}
			}
			report, err := c.report(e)
			if err != nil {
				return err
			}
			c.judge(i, nil, mf, nil, e.Traits, report)
		}
		if fetched(e) {
			continue
		}
		parent := root
		switch {
		case e.PID != nil && ids[*e.PID] != nil:
			parent = ids[*e.PID]
		default:
			for j := strings.LastIndex(e.Path, "!!"); j > 0; j = strings.LastIndex(e.Path[:j], "!!") {
				if p := paths[e.Path[:j]]; p != nil {
					parent = p
					break
				}
			}
		}
		if parent.Rel == "registry" || parent.Type == "registry" || len(parent.SHA) != 64 {
			c.out.Omitted["member of an omitted entry"]++
			continue
		}
		rel, ok := strings.CutPrefix(e.Path, parent.Path+"!!")
		if !ok {
			_, rel, _ = strings.Cut(e.Path[max(strings.LastIndex(e.Path, "!!"), 0):], "!!")
			rel = cmp.Or(rel, e.Path)
		}
		if rel == "" || len(rel) > 4096 {
			c.out.Omitted["member path empty or over 4096 bytes"]++
			continue
		}
		p, err := c.file(parent.SHA, parent.Size, parent.Type)
		if err != nil {
			return err
		}
		if p == i {
			c.out.Omitted["file inside itself"]++
			continue
		}
		c.members[p] = append(c.members[p], member{rel, i})
	}
	return nil
}

// refs records what the scanned artifact points at: the fetch records of the
// scan and the dependency references on each entry, whichever file of this
// result declared them. Which file that was stays in its report.
func (c *converter) refs(top map[string]json.RawMessage, entries []*entry) error {
	root := &c.out.Files[0]
	root.Refs = []scanresult.Ref{} // the scan looked; none found is a statement
	add := func(holder, locator, kind, content string) {
		_, ok := c.index[holder]
		name, version, requested := splitLocator(locator)
		ref := scanresult.Ref{Kind: kind, Name: name, Version: version, Requested: requested}
		if kind == "url_fetch" {
			ref.SHA256 = content
		}
		if !ok || ref.Check() != nil {
			c.out.Omitted["unusable reference"]++
			return
		}
		if !slices.Contains(root.Refs, ref) {
			root.Refs = append(root.Refs, ref)
		}
	}
	var fetched []struct {
		Kind    string `json:"kind"`
		Locator string `json:"locator"`
		Source  string `json:"source_sha256"`
		Content string `json:"content_sha256"`
	}
	if raw, ok := top["fetched"]; ok {
		if err := json.Unmarshal(raw, &fetched); err != nil {
			return fmt.Errorf("v7result: fetched: %w", err)
		}
	}
	for _, f := range fetched {
		add(f.Source, f.Locator, f.Kind, f.Content)
	}
	for _, e := range entries {
		for _, r := range e.Refs {
			if r.Kind == "dependency" {
				add(e.SHA, r.To, "dependency", "")
			}
		}
	}
	return nil
}

// claim carries an entry's identity block to file i. Reports older than the
// identity block say nothing by leaving it out, so a version 7 result never
// removes a stored claim; it only sets one.
func (c *converter) claim(i int, e *entry) {
	if e.Ident == nil || c.out.Files[i].Ident != nil {
		return
	}
	if _, err := scanresult.ClaimOf(e.Ident); err != nil {
		c.out.Omitted["identity block hopper cannot store"]++
		return
	}
	c.out.Files[i].Ident = e.Ident
}

// judge records the verdict, jurors and report of file i. Exactly one of
// root (the scanned file's ML section) and mf (a member's entry in it) is set
// when the ML ran. A nil report leaves the file without one.
func (c *converter) judge(i int, root *ml, mf *mlFile, in *llm, traits []trait, report []byte) {
	f := &c.out.Files[i]
	var level json.RawMessage
	var prob *float64
	model := ""
	switch {
	case root != nil:
		level, prob, model = either(root.Lvl, root.L), root.Prob, root.Version
	case mf != nil && mf.Verdict != nil:
		level, prob = mf.Verdict.Lvl, mf.Verdict.Prob
	case mf != nil:
		level, prob = either(mf.Lvl, mf.L), mf.Prob
	default:
	}
	firesAt := levelOf(level)
	verdict := opinion{Outcome: "ok", Class: c.class(firesAt), FiresAt: firesAt, Top: strongest(traits)}
	if root != nil {
		if class := classOf(either(root.Cls, root.Class)); class != "" {
			verdict.Class = class
		}
	}
	fl := floor(traits)
	if verdict.Class == "" {
		// No level was measured: the floor's reading stands alone, and a file
		// with nothing of note is benign. Version 8 always sends a class.
		verdict.Class = "benign"
		if fl != nil {
			verdict.Class = fl.Class
		}
	}
	f.Jurors = map[string]json.RawMessage{}
	if root != nil || mf != nil {
		mlOpinion := opinion{Class: c.class(firesAt), FiresAt: firesAt, Prob: prob, Model: model}
		if in != nil && in.Before != nil { // the model's reading before the interpreter moved it
			before := levelOf(in.Before.Lvl)
			mlOpinion.Class, mlOpinion.FiresAt, mlOpinion.Prob = c.class(before), before, cmp.Or(in.Before.Prob, prob)
		}
		if mlOpinion.Class != "" { // a model that measured no level gave no opinion
			f.Jurors["ml"] = mustJSON(mlOpinion)
		}
	}
	if fl != nil {
		f.Jurors["floor"] = mustJSON(fl)
	}
	if in != nil && (in.Grade != "" || in.Error != "" || in.Model != "") {
		reason := clip(in.Interpretation, maxReason)
		interp := opinion{Class: classOf(mustJSON(in.Grade)), Conf: in.Conf, Model: clip(in.Model, maxModel), Reason: reason, Inject: in.Inject}
		if interp.Class == "" {
			interp.Outcome, interp.Error = "error", cmp.Or(clip(in.Error, maxError), "no grade")
		}
		f.Jurors["llm"] = mustJSON(interp)
		verdict.Reason = reason
	}
	if len(f.Jurors) == 0 {
		f.Jurors = nil
	}
	f.Verdict = mustJSON(verdict)
	if report != nil {
		sum := sha256.Sum256(report)
		f.Report, f.ReportLine = sum[:], report
	}
}

// report is entry e's version 8 report, built as scan's report_line builds
// one: the entry without placement and without the dependency verdicts pinned
// onto it, each source in another file cited by that file's sha256 and a
// source in this file by nothing, a source naming no file dropped, and keys
// sorted at every level. Numbers keep their text.
func (c *converter) report(e *entry) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(e.raw))
	d.UseNumber()
	var obj map[string]any
	if err := d.Decode(&obj); err != nil {
		return nil, fmt.Errorf("v7result: report of %s: %w", e.SHA, err)
	}
	for _, key := range placement {
		delete(obj, key)
	}
	if traits, ok := obj["traits"].([]any); ok {
		traits = slices.DeleteFunc(traits, func(t any) bool {
			m, ok := t.(map[string]any)
			if !ok {
				return false
			}
			_, dep := m["dep"]
			return dep
		})
		for _, t := range traits {
			if m, ok := t.(map[string]any); ok {
				if from, ok := m["from"].([]any); ok {
					m["from"] = slices.DeleteFunc(from, func(source any) bool { return !c.cite(source, e.SHA) })
				}
			}
		}
		obj["traits"] = traits
		if len(traits) == 0 {
			delete(obj, "traits")
		}
	}
	if refs, ok := obj["refs"].([]any); ok {
		for _, declared := range refs {
			c.cite(declared, e.SHA)
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // as scan writes it
	if err := enc.Encode(obj); err != nil {
		return nil, fmt.Errorf("v7result: report of %s: %w", e.SHA, err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// cite replaces the report's file id in source with the cited file's sha256,
// or with nothing when the file is the report's own. It returns false when
// the id names no file, so the caller can drop the source.
func (c *converter) cite(source any, own string) bool {
	m, ok := source.(map[string]any)
	if !ok {
		return true
	}
	id, ok := m["file"]
	if !ok {
		return true
	}
	delete(m, "file")
	n, ok := id.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	sha, found := c.shas[i]
	if err != nil || !found {
		return false
	}
	if sha != own {
		m["sha256"] = sha
	}
	return true
}

// finish stamps every file and orders each container's members by path.
func (c *converter) finish(scan scanresult.Stamp) (*Converted, error) {
	for i := range c.out.Files {
		c.out.Files[i].Scan = scan
	}
	for p, list := range c.members {
		slices.SortFunc(list, func(a, b member) int { return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.child, b.child)) })
		list = slices.Compact(list)
		if len(list) > scanresult.MaxStored {
			c.out.Omitted["members over the cap"] += len(list) - scanresult.MaxStored
			list = list[:scanresult.MaxStored]
		}
		f := &c.out.Files[p]
		f.Children, f.Paths = make([]int, len(list)), make([]string, len(list))
		for j, m := range list {
			f.Children[j], f.Paths[j] = m.child, m.path
		}
	}
	return c.out, nil
}

// fetched reports whether an entry is a dependency the scan fetched rather than
// something inside its parent. Older reports lack rel; their fetched entries
// are named by locator, which no archive member's path is.
func fetched(e *entry) bool {
	if e.Rel == "fetched" {
		return true
	}
	return e.Rel == "" && !strings.Contains(e.Path, "!!") &&
		(strings.HasPrefix(e.Path, "pkg:") || strings.HasPrefix(e.Path, "https://") || strings.HasPrefix(e.Path, "http://"))
}

func (m *ml) files() []mlFile {
	if len(m.Files) > 0 {
		return m.Files
	}
	return m.FS
}

// levelOf reads a level: an integer, or nothing for null or an unknown shape.
func levelOf(raw json.RawMessage) *int {
	var n int
	if json.Unmarshal(raw, &n) != nil {
		return nil
	}
	return &n
}

// class grades a level at the deploy level; see gridMax.
func (c *converter) class(level *int) string {
	switch {
	case level == nil:
		return ""
	case *level < 0:
		return "benign"
	case *level <= c.level:
		return "hostile"
	case *level <= min(gridMax, max(suspiciousFloor, suspiciousFactor*c.level)),
		*level == 25001, *level == 25002, *level == 50001, *level == 50002:
		return "suspicious"
	default:
		return "benign"
	}
}

// classOf reads a class written as a name or as scan's 0, 1, 2.
func classOf(raw json.RawMessage) string {
	var n int
	if json.Unmarshal(raw, &n) == nil && n >= 0 && n <= 2 {
		return []string{"benign", "suspicious", "hostile"}[n]
	}
	var s string
	_ = json.Unmarshal(raw, &s) //nolint:errcheck // anything else is no class
	switch strings.ToLower(s) {
	case "benign", "suspicious", "hostile":
		return strings.ToLower(s)
	case "malicious":
		return "hostile"
	default:
		return ""
	}
}

// strongest returns at most three findings at crit 5, then crit 4.
func strongest(traits []trait) []scanresult.Finding {
	var top []scanresult.Finding
	for crit := 5; crit >= 4; crit-- {
		for _, t := range traits {
			if t.Crit == crit && t.ID != "" && len(top) < 3 {
				top = append(top, scanresult.Finding{ID: t.ID, Crit: t.Crit})
			}
		}
	}
	return top
}

// floor is the stand-in for scan's trait floor. It is absent when the
// findings convict nothing: the floor cannot say benign.
func floor(traits []trait) *opinion {
	var hostile, suspicious int
	for _, t := range traits {
		switch {
		case t.Crit >= 5:
			hostile++
		case t.Crit == 4:
			suspicious++
		default:
		}
	}
	switch {
	case hostile >= 1 || suspicious >= 2:
		return &opinion{Class: "hostile", Hostile: hostile, Suspicious: suspicious}
	case suspicious == 1:
		return &opinion{Class: "suspicious", Suspicious: suspicious}
	default:
		return nil
	}
}

// splitLocator separates a PURL's version from its name, dropping qualifiers
// and subpath, and returns the version constraint a qualifier carried (fletch
// writes vers, and cargo references version_requirement) when it is not the
// exact version. A URL is a name with no version.
func splitLocator(loc string) (name, version, requested string) {
	switch {
	case strings.HasPrefix(loc, "https://"), strings.HasPrefix(loc, "http://"):
		return loc, "", ""
	case !strings.HasPrefix(loc, "pkg:"):
		return "", "", ""
	}
	loc, _, _ = strings.Cut(loc, "#")
	loc, qualifiers, _ := strings.Cut(loc, "?")
	// PURL qualifiers are percent-encoded, not form-encoded: a '+' is a '+'.
	for kv := range strings.SplitSeq(qualifiers, "&") {
		key, value, _ := strings.Cut(kv, "=")
		if key == "vers" || key == "version_requirement" {
			if v, err := url.PathUnescape(value); err == nil && requested == "" {
				requested = v
			}
		}
	}
	name = loc
	if at := strings.LastIndexByte(loc, '@'); at > strings.LastIndexByte(loc, '/') {
		name, version = loc[:at], loc[at+1:]
	}
	if requested == version {
		requested = ""
	}
	return name, version, requested
}

// either returns a unless it is empty, then b: a field spelled two ways.
func either(a, b json.RawMessage) json.RawMessage {
	if len(a) > 0 {
		return a
	}
	return b
}

// mustJSON marshals values that cannot fail to marshal: strings, the structs
// above, and raw messages that were themselves decoded from valid JSON.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("v7result: marshal %T: %v", v, err))
	}
	return b
}
