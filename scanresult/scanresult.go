// Package scanresult is the result body an analysis worker uploads to hopper,
// version 8: what one scan concluded about an artifact and the files inside
// it. The format is specified in scan's JSON_PLAN.md. This package holds its
// Go types and the checks every body must pass; it stores nothing, so that
// whoever reads or builds a body can import it.
//
// A body is JSON lines: a header, a line per file, then each file's report.
// Version 7 results are converted to the same types by package v7result.
// Whatever produced them, files are stored only once [Check] passes them.
package scanresult

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits on a result body. They bound what one upload can make hopper hold or
// store. A body over any of them is malformed.
const (
	Version  = 8         // of the body format
	MaxFiles = 1_000_000 // file lines in one body
	// MaxMembers bounds the immediate members of one container in a body:
	// scan's cap on what it keeps, and so a bound on what one upload can
	// make a contents row hold. Raise it here before raising scan's.
	MaxMembers = 256
	// MaxStored bounds them in any result hopper stores, as the contents
	// table's check does: version 7 results, and the migration that
	// converts them, list more than scan keeps.
	MaxStored  = 100_000
	MaxSummary = 900      // bytes of one verdict, juror or scanner object
	MaxIdent   = 8192     // bytes of one identity block
	MaxLine    = 64 << 20 // bytes of one line, a report included
	MaxPath    = 4096
	MaxName    = 2048
	MaxVersion = 256
	MaxType    = 64
	MaxStamp   = 256 // bytes of a stamp's engine, ruleset or worker, and of a scanner's
)

// Stamp says which scan produced a verdict. It is the only part of a result
// that differs between two scans of the same bytes under the same rules.
type Stamp struct {
	At      time.Time `json:"at"`
	Engine  string    `json:"engine"`
	Ruleset string    `json:"ruleset"`
	Worker  string    `json:"worker"`
	Level   int       `json:"level"`
	MS      int64     `json:"ms"`
}

// Ref is something a scanned artifact points at: a package or a URL.
type Ref struct {
	Kind string `json:"kind"` // dependency, command or url_fetch
	Name string `json:"name"` // a PURL without its version, or a URL
	// Version is the exact version the ref is bound to: the declared one if
	// it was exact, else the one scan resolved, else empty.
	Version string `json:"version,omitempty"`
	// Requested is the constraint as written, empty when it was exact.
	Requested string `json:"requested,omitempty"`
	// SHA256 is, for a url_fetch ref, the hex digest of what scan fetched.
	SHA256 string `json:"sha256,omitempty"`
}

// File is everything one result says about one file.
type File struct {
	// Verdict is atomscan's verdict object. Nil means the file is only named,
	// as a member or a reference target, and was not judged by this scan.
	Verdict json.RawMessage
	// Jurors holds one object per juror that ran, keyed by juror name.
	Jurors map[string]json.RawMessage
	// Scanners holds one object per third-party scanner that ran, keyed by
	// its name. A scanner it does not name, or a nil map, is no statement:
	// that scanner's stored opinion stands. Only the scanner itself replaces
	// its row, so an upload from a host that does not run it (atomscan
	// --hopper, a worker without clamd) cannot erase what it found.
	Scanners map[string]json.RawMessage
	Type     string
	SHA256   []byte
	// Report is the sha256 of this file's report, and ReportLine the report
	// itself as it was uploaded; both nil if it has none.
	Report     []byte
	ReportLine []byte
	// Children index other files of the same result; Paths[i] is where
	// Children[i] sits in this file. Nil means the scan did not say; empty
	// means it looked and found none.
	Children []int
	Paths    []string
	// Refs follows the same rule: nil leaves stored references alone. A
	// version 8 body states them on the scanned artifact only.
	Refs []Ref
	// Ident is what the file says it is: the analyzer's identity block, kept
	// as it came. Nil means the scan did not say and the stored claim stands;
	// JSON null means it read the file and the file claims nothing.
	Ident json.RawMessage
	Scan  Stamp
	Size  int64
}

// Jurors names the components of atomdrift's verdict that can state an
// opinion on a file line. The drift jurors are isomer's: they judge a release
// against an earlier one.
var Jurors = []string{"floor", "ml", "llm", "drift_heuristic", "drift_llm"}

// Scanners names the third-party scanners a body may carry. Any other name is
// rejected: a scanner is added to hopper's schema, and here, before it is sent.
var Scanners = []string{"clamav", "malcontent", "guarddog"}

var refKinds = map[string]bool{"dependency": true, "command": true, "url_fetch": true}

// ErrMalformed is wrapped by every error that says the body itself is wrong,
// so a caller can tell a bad upload from a failing database.
var ErrMalformed = errors.New("malformed result body")

type headerLine struct {
	Scan  Stamp `json:"scan"`
	V     int   `json:"v"`
	Files int   `json:"files"`
}

type fileLine struct {
	Contents *struct {
		Children []int    `json:"children"`
		Paths    []string `json:"paths"`
	} `json:"contents"`
	Refs           *[]Ref                     `json:"refs"`
	SHA256         string                     `json:"sha256"`
	Type           string                     `json:"type"`
	Report         string                     `json:"report"`
	Verdict        json.RawMessage            `json:"verdict"`
	ML             json.RawMessage            `json:"ml"`
	Floor          json.RawMessage            `json:"floor"`
	LLM            json.RawMessage            `json:"llm"`
	DriftHeuristic json.RawMessage            `json:"drift_heuristic"`
	DriftLLM       json.RawMessage            `json:"drift_llm"`
	Scanners       map[string]json.RawMessage `json:"scanners"`
	Ident          json.RawMessage            `json:"ident"`
	Size           int64                      `json:"size"`
}

// Decode parses a version 8 result body, already decompressed: its header,
// a line per file, then the report of each file that names one, in file
// order. The body is taken whole rather than read from the connection so that
// storing it never waits on a sender while holding row locks. The files alias
// body. Decode checks the body's shape; [Check] checks what it says.
func Decode(body []byte) ([]File, error) {
	var h headerLine
	rest, err := line(body, &h)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	switch {
	case h.V != Version:
		return nil, fmt.Errorf("%w: header: version %d, want %d", ErrMalformed, h.V, Version)
	case h.Files < 1 || h.Files > MaxFiles:
		return nil, fmt.Errorf("%w: header: %d files, want 1 to %d", ErrMalformed, h.Files, MaxFiles)
	case h.Scan.At.IsZero() || h.Scan.Ruleset == "":
		return nil, fmt.Errorf("%w: header: scan.at and scan.ruleset are required", ErrMalformed)
	default:
	}
	h.Scan.At = h.Scan.At.UTC()
	// The header's count is the sender's word: the slice grows with the
	// lines actually sent.
	files := make([]File, 0, min(h.Files, 1024))
	for i := range h.Files {
		var l fileLine
		if rest, err = line(rest, &l); err != nil {
			return nil, fmt.Errorf("%w: file %d: %w", ErrMalformed, i, err)
		}
		f, err := l.file()
		if err == nil && len(f.Children) > MaxMembers {
			err = fmt.Errorf("contents: %d children, limit %d", len(f.Children), MaxMembers)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: file %d: %w", ErrMalformed, i, err)
		}
		f.Scan = h.Scan
		files = append(files, f)
	}
	for i := range files {
		if files[i].Report == nil {
			continue
		}
		if files[i].ReportLine, rest, err = cut(rest); err != nil {
			return nil, fmt.Errorf("%w: report of file %d: %w", ErrMalformed, i, err)
		}
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: %d bytes after the last report", ErrMalformed, len(rest))
	}
	return files, nil
}

// line decodes the first line of body strictly: a field this version does not
// define is an error, not something to drop silently.
func line(body []byte, v any) (rest []byte, err error) {
	first, rest, err := cut(body)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(first))
	dec.DisallowUnknownFields()
	return rest, dec.Decode(v)
}

// cut returns the first line of body, without its newline, and what follows.
// A final line without a newline is still a line.
func cut(body []byte) (first, rest []byte, err error) {
	if len(body) == 0 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	first, rest, _ = bytes.Cut(body, []byte{'\n'})
	if len(first) > MaxLine {
		return nil, nil, fmt.Errorf("line longer than %d bytes", MaxLine)
	}
	return bytes.TrimSuffix(first, []byte{'\r'}), rest, nil
}

// file converts one file line.
func (l *fileLine) file() (File, error) {
	f := File{Type: l.Type, Size: l.Size, Verdict: l.Verdict, Scanners: l.Scanners}
	var err error
	if f.SHA256, err = digest(l.SHA256); err != nil {
		return File{}, fmt.Errorf("sha256: %w", err)
	}
	if l.Report != "" {
		if f.Report, err = digest(l.Report); err != nil {
			return File{}, fmt.Errorf("report: %w", err)
		}
	}
	for name, obj := range map[string]json.RawMessage{
		"floor": l.Floor, "ml": l.ML, "llm": l.LLM, "drift_heuristic": l.DriftHeuristic, "drift_llm": l.DriftLLM,
	} {
		if obj == nil {
			continue
		}
		if f.Jurors == nil {
			f.Jurors = map[string]json.RawMessage{}
		}
		f.Jurors[name] = obj
	}
	var verdict struct {
		Outcome string `json:"outcome"`
	}
	if f.Verdict != nil && json.Unmarshal(f.Verdict, &verdict) == nil && (verdict.Outcome == "" || verdict.Outcome == "ok") {
		// The scan read the file, so a line without an identity block says
		// the file claims nothing.
		f.Ident = json.RawMessage("null")
	}
	if l.Ident != nil {
		f.Ident = l.Ident
	}
	if l.Contents != nil {
		f.Children, f.Paths = l.Contents.Children, l.Contents.Paths
		if f.Children == nil {
			f.Children = []int{}
		}
	}
	if l.Refs != nil {
		f.Refs = *l.Refs
		if f.Refs == nil {
			f.Refs = []Ref{}
		}
	}
	return f, nil
}

// Check reports whether files can be stored as one result, files[0] being
// the scanned artifact: every limit, every rule of the format, and every
// value PostgreSQL would refuse, so that a result it passes cannot fail at
// the database the same way on every retry. Its errors wrap ErrMalformed.
func Check(files []File) error {
	if len(files) < 1 || len(files) > MaxFiles {
		return fmt.Errorf("%w: %d files, want 1 to %d", ErrMalformed, len(files), MaxFiles)
	}
	seen := make(map[[32]byte]bool, len(files))
	for i := range files {
		if err := files[i].check(i, len(files)); err != nil {
			return fmt.Errorf("%w: file %d: %w", ErrMalformed, i, err)
		}
		key := [32]byte(files[i].SHA256)
		if seen[key] {
			return fmt.Errorf("%w: file %d repeats %x", ErrMalformed, i, key)
		}
		seen[key] = true
	}
	return nil
}

// check checks file self of a result of n files.
func (f *File) check(self, n int) error {
	s := f.Scan
	switch {
	case len(f.SHA256) != 32:
		return errors.New("sha256 is not 32 bytes")
	case f.Size < 0 || len(f.Type) > MaxType:
		return errors.New("size or type out of range")
	case len(s.Engine) > MaxStamp || len(s.Ruleset) > MaxStamp || len(s.Worker) > MaxStamp:
		return fmt.Errorf("scan engine, ruleset or worker over %d bytes", MaxStamp)
	case !utf8.ValidString(s.Engine+s.Ruleset+s.Worker+f.Type) || strings.ContainsRune(s.Engine+s.Ruleset+s.Worker+f.Type, 0):
		return errors.New("scan engine, ruleset, worker or type is not UTF-8 text")
	case (f.Report == nil) != (f.ReportLine == nil):
		return errors.New("a report digest without a report, or a report without a digest")
	default:
	}
	if f.Report != nil {
		if sum := sha256.Sum256(f.ReportLine); !bytes.Equal(sum[:], f.Report) {
			return fmt.Errorf("report hashes to %x, the file line says %x", sum, f.Report)
		}
	}
	if self > 0 && (f.Jurors["llm"] != nil || f.Jurors["drift_heuristic"] != nil || f.Jurors["drift_llm"] != nil ||
		f.Refs != nil || f.Scanners != nil) {
		// Only the scanned artifact's line speaks for these, so a member's
		// line can neither set them nor, by leaving them out, remove them.
		return errors.New("llm, drift_heuristic, drift_llm, scanners or refs on a member's line")
	}
	if f.Verdict == nil && (f.Jurors != nil || f.Report != nil || f.Scanners != nil) {
		return errors.New("jurors, scanners or a report without a verdict")
	}
	for name, obj := range f.Scanners {
		if _, err := SplitScanner(name, obj); err != nil {
			return fmt.Errorf("scanners: %s: %w", name, err)
		}
	}
	for name, obj := range f.Jurors {
		if !slices.Contains(Jurors, name) {
			return fmt.Errorf("unknown juror %q", name)
		}
		if _, err := opinion(obj); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if f.Verdict != nil {
		ok, err := opinion(f.Verdict)
		if err != nil {
			return fmt.Errorf("verdict: %w", err)
		}
		if !ok && f.Jurors != nil {
			return errors.New("jurors on a scan that did not succeed")
		}
	}
	if f.Ident != nil && string(f.Ident) != "null" {
		if _, err := ClaimOf(f.Ident); err != nil {
			return fmt.Errorf("ident: %w", err)
		}
	}
	if f.Children != nil {
		if err := members(f.Children, f.Paths, self, n); err != nil {
			return fmt.Errorf("contents: %w", err)
		}
	}
	for _, r := range f.Refs {
		if err := r.Check(); err != nil {
			return fmt.Errorf("refs: %w", err)
		}
	}
	return nil
}

func digest(hexed string) ([]byte, error) {
	b, err := hex.DecodeString(hexed)
	if err != nil || len(b) != 32 {
		return nil, errors.New("not a sha256 in hex")
	}
	return b, nil
}

var (
	outcomes = map[string]bool{"": true, "ok": true, "unsupported": true, "timeout": true, "error": true}
	classes  = map[string]bool{"benign": true, "suspicious": true, "hostile": true}
)

// opinion checks that a verdict or juror object is a JSON object small enough
// to be stored inline, that it carries a class exactly when its outcome is
// ok, which it reports, and that its fires_at, if any, is a level the
// verdicts table can hold: an integer from -1 to 32767.
func opinion(obj json.RawMessage) (ok bool, err error) {
	if len(obj) > MaxSummary {
		return false, fmt.Errorf("%d bytes, limit %d", len(obj), MaxSummary)
	}
	var o struct {
		Outcome string          `json:"outcome"`
		Class   string          `json:"class"`
		FiresAt json.RawMessage `json:"fires_at"`
	}
	if len(obj) == 0 || obj[0] != '{' || json.Unmarshal(obj, &o) != nil {
		return false, errors.New("not a JSON object")
	}
	if err := CheckJSONB(obj); err != nil {
		return false, err
	}
	ok = o.Outcome == "" || o.Outcome == "ok"
	switch {
	case !outcomes[o.Outcome]:
		return false, fmt.Errorf("outcome %q", o.Outcome)
	case ok && !classes[o.Class]:
		return false, fmt.Errorf("class %q", o.Class)
	case !ok && o.Class != "":
		return false, fmt.Errorf("class %q on outcome %q", o.Class, o.Outcome)
	case o.FiresAt != nil && string(o.FiresAt) != "null":
		if n, err := strconv.ParseInt(string(o.FiresAt), 10, 16); err != nil || n < -1 {
			return false, fmt.Errorf("fires_at %.20s, want an integer from -1 to 32767", o.FiresAt)
		}
		return ok, nil
	default:
		return ok, nil
	}
}

// Finding is one of a file's strongest traits, as a verdict's top lists
// them: crit 4 is suspicious, 5 hostile.
type Finding struct {
	ID   string `json:"id"`
	Crit int    `json:"crit"`
}

// ScannerOpinion is a third-party scanner's object in two parts: what it
// found, and what it says about itself. The two are kept apart because a new
// signature database that finds the same thing is not a new opinion.
type ScannerOpinion struct {
	Engine  string          // the scanner's own version
	Ruleset string          // the rules or signature database it judged by
	Opinion json.RawMessage // the object without engine, ruleset or db
}

// SplitScanner checks the object a third-party scanner named name reported,
// and splits it.
func SplitScanner(name string, obj json.RawMessage) (ScannerOpinion, error) {
	var stamp struct {
		Engine  string `json:"engine"`
		Ruleset string `json:"ruleset"`
		DB      string `json:"db"` // the ruleset, as a signature scanner calls it
		Report  string `json:"report"`
	}
	if !slices.Contains(Scanners, name) {
		return ScannerOpinion{}, errors.New("not a scanner hopper knows")
	}
	if _, err := opinion(obj); err != nil {
		return ScannerOpinion{}, err
	}
	found := map[string]json.RawMessage{}
	if json.Unmarshal(obj, &stamp) != nil || json.Unmarshal(obj, &found) != nil {
		return ScannerOpinion{}, errors.New("engine, ruleset, db and report are strings")
	}
	if stamp.Report != "" {
		return ScannerOpinion{}, errors.New("a scanner's report is not stored yet")
	}
	if len(stamp.Engine) > MaxStamp || len(cmp.Or(stamp.Ruleset, stamp.DB)) > MaxStamp {
		return ScannerOpinion{}, fmt.Errorf("engine or ruleset over %d bytes", MaxStamp)
	}
	for _, key := range []string{"engine", "ruleset", "db", "report"} {
		delete(found, key)
	}
	rest, err := json.Marshal(found)
	if err != nil {
		return ScannerOpinion{}, err
	}
	return ScannerOpinion{Engine: stamp.Engine, Ruleset: cmp.Or(stamp.Ruleset, stamp.DB), Opinion: rest}, nil
}

// CheckJSONB reports why PostgreSQL would refuse valid JSON as jsonb: text in
// it that is not UTF-8, an escaped NUL, or an escaped UTF-16 surrogate that
// is not half of a pair (Go decodes one as U+FFFD; PostgreSQL refuses it).
// Refused at the database, the write would fail the same way every time it
// was retried.
func CheckJSONB(obj []byte) error {
	if !utf8.Valid(obj) {
		return errors.New("not UTF-8")
	}
	// hex4 is the code unit a \u escape spells, -1 if b does not start with one.
	hex4 := func(b []byte) rune {
		if len(b) < 4 {
			return -1
		}
		n, err := strconv.ParseUint(string(b[:4]), 16, 16)
		if err != nil {
			return -1
		}
		return rune(n)
	}
	low := func(u rune) bool { return u >= 0xDC00 && u <= 0xDFFF }
	for i := 0; i < len(obj)-1; i++ {
		if obj[i] != '\\' {
			continue
		}
		i++ // the escaped character, which may itself be a backslash
		if obj[i] != 'u' {
			continue
		}
		if i+5 > len(obj) {
			return errors.New("not JSON")
		}
		switch u := hex4(obj[i+1:]); {
		case u == 0:
			return errors.New("holds a NUL")
		case u >= 0xD800 && u <= 0xDBFF:
			if !bytes.HasPrefix(obj[i+5:], []byte(`\u`)) || !low(hex4(obj[i+7:])) {
				return errors.New("holds half a UTF-16 surrogate pair")
			}
			i += 6 // to the low half's u
		case low(u):
			return errors.New("holds half a UTF-16 surrogate pair")
		default:
		}
		i += 4
	}
	return nil
}

// Claim is what an identity block claims that hopper searches by. A field is
// empty when the block does not make that claim, or makes one too long to be
// a name anybody would look up.
type Claim struct {
	Name, Version, Signer string
}

// ClaimOf checks that an identity block can be stored, and returns what it
// claims. The signer is the certificate's organization, or failing that its
// common name.
func ClaimOf(ident json.RawMessage) (Claim, error) {
	var block struct {
		Name    struct{ Value string } `json:"name"`
		Version struct{ Value string } `json:"version"`
		Signer  struct {
			Organization string `json:"organization"`
			CommonName   string `json:"common_name"`
		} `json:"signer"`
	}
	switch {
	case len(ident) > MaxIdent:
		return Claim{}, fmt.Errorf("%d bytes, limit %d", len(ident), MaxIdent)
	case len(ident) == 0 || ident[0] != '{' || json.Unmarshal(ident, &block) != nil:
		return Claim{}, errors.New("not a JSON object")
	default:
	}
	if err := CheckJSONB(ident); err != nil {
		return Claim{}, err
	}
	c := Claim{block.Name.Value, block.Version.Value, cmp.Or(block.Signer.Organization, block.Signer.CommonName)}
	if len(c.Name) > MaxName {
		c.Name = ""
	}
	if len(c.Version) > MaxVersion {
		c.Version = ""
	}
	if len(c.Signer) > MaxName {
		c.Signer = ""
	}
	return c, nil
}

func members(children []int, paths []string, self, n int) error {
	if len(children) != len(paths) || len(children) > MaxStored {
		return fmt.Errorf("%d children, %d paths, limit %d", len(children), len(paths), MaxStored)
	}
	for i, c := range children {
		if c < 0 || c >= n || c == self {
			return fmt.Errorf("child %d is not another file of this result", c)
		}
		if paths[i] == "" || len(paths[i]) > MaxPath {
			return fmt.Errorf("path %d is empty or longer than %d bytes", i, MaxPath)
		}
	}
	return nil
}

// Check reports whether r can be stored: a known kind and a PURL or URL name.
func (r Ref) Check() error {
	if !refKinds[r.Kind] {
		return fmt.Errorf("kind %q", r.Kind)
	}
	if len(r.Name) > MaxName || len(r.Version) > MaxVersion || len(r.Requested) > MaxVersion {
		return errors.New("name, version or requested too long")
	}
	if r.SHA256 != "" {
		if r.Kind != "url_fetch" {
			return fmt.Errorf("sha256 on a %s ref", r.Kind)
		}
		if _, err := digest(r.SHA256); err != nil {
			return fmt.Errorf("sha256: %w", err)
		}
	}
	for _, prefix := range []string{"pkg:", "https://", "http://"} {
		if strings.HasPrefix(r.Name, prefix) {
			return nil
		}
	}
	return fmt.Errorf("name %q is neither a PURL nor a URL", r.Name)
}
