package hopper

import (
	"encoding/json"
	"errors"
	"fmt"
)

// archive.go losslessly decomposes a scanner analysis envelope into
// content-addressed pieces, and reassembles it with the exact inverse.
//
// An envelope is the scanner's `{"ml": {...}, "llm": {...}, "raw": {...}}`
// output. For an archive, `raw.files` (alias `fs`) is a flat, ordered list of
// file entries: one container at depth 0 and the embedded members at depth > 0.
// A member entry carries the heavy analysis — `ctx`/`traits`/`facts` — that
// recurs identically wherever that file appears, so storing it once per archive
// is wasteful and storing copies invites drift.
//
// [Split] factors every member entry out into a [Leaf] — a self-contained
// single-file envelope keyed by the member's content SHA-256 — and leaves the
// parent holding the container in full plus a placement-only reference for each
// member, in place and in order. [Join] is the exact inverse: it restores each
// member entry from its leaf, re-stamping the per-archive placement (id, depth,
// path) the reference preserved. Only `raw.files` is rewritten; `ml`, `llm`, and
// every other section pass through untouched, so they round-trip for free.
//
// The contract is a single law, verified semantically (parsed-JSON deep
// equality, not byte equality) in archive_test.go:
//
//	Join(Split(env)) ≅ env
//
// Dedup falls out: a member keys on its content SHA-256, so the same file across
// many archives is one leaf. The parent never holds member analysis — only
// references — so it cannot drift out of sync with the leaves it points at.

// Envelope reassembles a sample's analysis envelope from its stored columns:
// `{"ml": litmus_result, "llm": llm_result, "raw": cleave_result}`. Empty or
// invalid columns are omitted. It is the inverse of how an incoming result is
// destructured into columns for storage, and the unit Split and Join operate on.
func Envelope(s *Sample) []byte {
	top := make(map[string]json.RawMessage, 3)
	for key, col := range map[string][]byte{"ml": s.LitmusResult, "llm": s.LLMResult, "raw": s.CleaveResult} {
		if len(col) > 0 && json.Valid(col) {
			top[key] = col
		}
	}
	return mustMarshal(top)
}

// Reassemble returns a parent archive's full analysis envelope, restoring each
// member from its leaf. members are the parent's exploded member samples in any
// order; a member without a stored leaf degrades to its reference stub, and a
// non-archive sample returns its own envelope unchanged. This is the read-side
// counterpart to the write-side Split — both live here so the decomposition and
// its inverse are tested against each other.
func Reassemble(parent *Sample, members []*Sample) ([]byte, error) {
	leaves := make(map[string][]byte, len(members))
	for _, m := range members {
		leaves[m.SHA256] = Envelope(m)
	}
	joined, err := Join(Envelope(parent), func(sha string) ([]byte, bool) {
		env, ok := leaves[sha]
		return env, ok
	})
	if err != nil {
		return nil, err
	}
	return clearCompactionMarkers(joined, leaves)
}

// clearCompactionMarkers drops the storage-time "truncated" flag — the envelope
// is reassembled now — and rewrites "omitted_files" to the members that remained
// references because no leaf was supplied. This keeps a reader from treating a
// reassembled envelope as still-compacted (and re-reassembling it forever) while
// staying honest about a partial hydration.
func clearCompactionMarkers(envelope []byte, have map[string][]byte) ([]byte, error) {
	top, err := decodeObject(envelope)
	if err != nil {
		return nil, fmt.Errorf("hopper: finalize markers: %w", err)
	}
	raw, err := section(top, "raw")
	if err != nil {
		return nil, fmt.Errorf("hopper: finalize markers raw: %w", err)
	}
	if raw.obj == nil {
		return envelope, nil
	}
	omitted := 0
	for _, f := range raw.files {
		entry, derr := decodeObject(f)
		if derr != nil {
			continue
		}
		if entryDepth(entry) > 0 {
			if _, ok := have[entrySHA(entry)]; !ok {
				omitted++
			}
		}
	}
	delete(raw.obj, "truncated")
	if omitted > 0 {
		raw.obj["omitted_files"] = mustMarshal(omitted)
	} else {
		delete(raw.obj, "omitted_files")
	}
	top["raw"] = mustMarshal(raw.obj)
	return mustMarshal(top), nil
}

// Leaf is one archive member's analysis, factored out of its parent and keyed by
// the member's content SHA-256. Envelope is a self-contained single-file
// `{"ml":...,"raw":...}` — what the member would produce if scanned alone — so it
// dedups across every archive that contains the file and renders directly when
// viewed on its own.
type Leaf struct {
	SHA256   string
	Envelope []byte
}

// placementKeys are the per-archive fields of a file entry: where the file sits
// in *this* archive, as opposed to what the file *is*. Split strips them from
// the leaf (so identical content dedups to identical bytes) and preserves them
// on the reference; Join copies them back. Depth travels under "dp" (v4–v7) or
// "depth" (v8); both are listed so either generation round-trips.
var placementKeys = []string{"id", "dp", "depth", "path"}

// refKeys are the fields kept on a member's parent reference: its placement plus
// the light identity/summary fields a reader needs to list members without
// hydrating their leaves. The heavy fields (ctx/traits/facts) are deliberately
// absent — dropping them from the parent is the storage win. Size travels under
// "size" (v7+) or "sz" (v4); both are kept so either generation summarizes.
var refKeys = []string{"id", "sha", "path", "type", "dp", "depth", "size", "sz", "risk", "mol"}

// Split decomposes an archive envelope into its parent (container plus member
// references) and one leaf per member. A non-archive envelope — no `raw.files`,
// or a single file — is returned unchanged with no leaves, so callers can run
// every envelope through Split unconditionally.
func Split(envelope []byte) (parent []byte, leaves []Leaf, err error) {
	top, err := decodeObject(envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("hopper: split envelope: %w", err)
	}
	raw, err := section(top, "raw")
	if err != nil {
		return nil, nil, fmt.Errorf("hopper: split raw: %w", err)
	}
	if len(raw.files) <= 1 {
		return envelope, nil, nil // not an archive; nothing to factor out
	}

	// Member ML entries (light) ride along in each leaf so a member viewed on its
	// own still has its verdict. The parent keeps ml.files whole, so this never
	// affects the round-trip.
	ml, err := section(top, "ml")
	if err != nil {
		return nil, nil, fmt.Errorf("hopper: split ml: %w", err)
	}
	mlByID := indexByID(ml.files)

	leaves = make([]Leaf, 0, len(raw.files)-1)
	for i, rawEntry := range raw.files {
		entry, derr := decodeObject(rawEntry)
		if derr != nil {
			return nil, nil, fmt.Errorf("hopper: split raw.files[%d]: %w", i, derr)
		}
		if entryDepth(entry) == 0 {
			continue // the container stays in the parent, in full
		}
		sha := entrySHA(entry)
		if sha == "" {
			continue // unidentifiable member: leave it inline rather than orphan it
		}

		leafEnv, lerr := buildLeaf(entry, raw, ml, mlByID[entryID(entry)])
		if lerr != nil {
			return nil, nil, fmt.Errorf("hopper: split build leaf %s: %w", sha, lerr)
		}
		leaves = append(leaves, Leaf{SHA256: sha, Envelope: leafEnv})
		raw.files[i] = mustMarshal(pick(entry, refKeys))
	}

	raw.obj[raw.key] = mustMarshal(raw.files)
	top["raw"] = mustMarshal(raw.obj)
	return mustMarshal(top), leaves, nil
}

// Join reverses Split: it restores every member entry in the parent's raw.files
// from its leaf, re-stamping the placement the reference preserved. lookup
// returns a member's leaf envelope by content SHA-256; a member whose leaf is
// absent (not yet analyzed, or beyond a fetch cap) is left as its reference, so
// a partial hydration degrades to today's stub rather than failing.
func Join(parent []byte, lookup func(sha string) (envelope []byte, ok bool)) ([]byte, error) {
	top, err := decodeObject(parent)
	if err != nil {
		return nil, fmt.Errorf("hopper: join envelope: %w", err)
	}
	raw, err := section(top, "raw")
	if err != nil {
		return nil, fmt.Errorf("hopper: join raw: %w", err)
	}
	if len(raw.files) == 0 {
		return parent, nil
	}

	for i, rawEntry := range raw.files {
		ref, derr := decodeObject(rawEntry)
		if derr != nil {
			return nil, fmt.Errorf("hopper: join raw.files[%d]: %w", i, derr)
		}
		if entryDepth(ref) == 0 {
			continue // container, already whole
		}
		leafEnv, ok := lookup(entrySHA(ref))
		if !ok {
			continue // leaf unavailable: keep the reference as a stub
		}
		restored, rerr := restoreMember(ref, leafEnv)
		if rerr != nil {
			return nil, fmt.Errorf("hopper: join member %s: %w", entrySHA(ref), rerr)
		}
		raw.files[i] = restored
	}

	raw.obj[raw.key] = mustMarshal(raw.files)
	top["raw"] = mustMarshal(raw.obj)
	return mustMarshal(top), nil
}

// buildLeaf assembles a member's standalone envelope: each section's metadata
// (everything but the file list) with a single-element file list holding the
// member's placement-stripped entry. The raw entry is required; the ml entry
// rides along when present. llm is intentionally omitted — interpretation is a
// property of the whole sample, not of a member viewed alone.
func buildLeaf(entry map[string]json.RawMessage, raw, ml fileSection, mlEntry json.RawMessage) ([]byte, error) {
	leaf := map[string]json.RawMessage{"raw": leafSection(raw, drop(entry, placementKeys))}
	if ml.obj != nil && len(mlEntry) > 0 {
		canonical, err := decodeObject(mlEntry)
		if err != nil {
			return nil, fmt.Errorf("ml entry: %w", err)
		}
		leaf["ml"] = leafSection(ml, drop(canonical, placementKeys))
	}
	return json.Marshal(leaf)
}

// leafSection rebuilds a section around a single canonical file entry, carrying
// over the section's envelope-level metadata.
func leafSection(s fileSection, entry map[string]json.RawMessage) json.RawMessage {
	out := meta(s.obj, s.key)
	out[s.key] = mustMarshal([]json.RawMessage{mustMarshal(entry)})
	return mustMarshal(out)
}

// restoreMember reconstructs an original member entry from its parent reference
// and its leaf: the leaf's raw entry holds the content, the reference restores
// the placement Split stripped. The result equals the original entry key-for-key
// because leaf = original − placement and ref ⊇ placement.
func restoreMember(ref map[string]json.RawMessage, leafEnv []byte) (json.RawMessage, error) {
	top, err := decodeObject(leafEnv)
	if err != nil {
		return nil, fmt.Errorf("leaf envelope: %w", err)
	}
	raw, err := section(top, "raw")
	if err != nil {
		return nil, fmt.Errorf("leaf raw: %w", err)
	}
	if len(raw.files) == 0 {
		return nil, errors.New("leaf has no file entry")
	}
	member, err := decodeObject(raw.files[0])
	if err != nil {
		return nil, fmt.Errorf("leaf raw.files[0]: %w", err)
	}
	for _, k := range placementKeys {
		if v, ok := ref[k]; ok {
			member[k] = v
		}
	}
	return json.Marshal(member)
}

// fileSection is one envelope subsection ("ml" or "raw"): its mutable object,
// the file list within, and the key that list lives under ("files", or the
// legacy "fs"). A missing section yields a nil obj and empty files so callers can
// branch on len(files) without nil checks.
type fileSection struct {
	obj   map[string]json.RawMessage
	key   string
	files []json.RawMessage
}

// section extracts an envelope subsection by name.
func section(top map[string]json.RawMessage, name string) (fileSection, error) {
	blob, ok := top[name]
	if !ok || len(blob) == 0 {
		return fileSection{key: "files"}, nil
	}
	obj, err := decodeObject(blob)
	if err != nil {
		return fileSection{}, fmt.Errorf("parse %s: %w", name, err)
	}
	key := "files"
	listBlob := obj["files"]
	if len(listBlob) == 0 {
		key = "fs"
		listBlob = obj["fs"]
	}
	var files []json.RawMessage
	if len(listBlob) > 0 {
		if err := json.Unmarshal(listBlob, &files); err != nil {
			return fileSection{}, fmt.Errorf("parse %s.%s: %w", name, key, err)
		}
	}
	return fileSection{obj: obj, files: files, key: key}, nil
}

// meta copies a section's metadata — every key except the file list — so a leaf
// inherits the envelope-level fields (version, traits revision, …) the member
// needs to stand alone.
func meta(obj map[string]json.RawMessage, filesKey string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		if k == filesKey {
			continue
		}
		out[k] = v
	}
	return out
}

// pick returns a copy of obj keeping only keys in want (those present).
func pick(obj map[string]json.RawMessage, want []string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(want))
	for _, k := range want {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
	return out
}

// drop returns a copy of obj without the keys in remove.
func drop(obj map[string]json.RawMessage, remove []string) map[string]json.RawMessage {
	skip := make(map[string]struct{}, len(remove))
	for _, k := range remove {
		skip[k] = struct{}{}
	}
	out := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		if _, ok := skip[k]; ok {
			continue
		}
		out[k] = v
	}
	return out
}

// indexByID maps each file entry to its "id" for correlating ml and raw lists.
func indexByID(files []json.RawMessage) map[int]json.RawMessage {
	out := make(map[int]json.RawMessage, len(files))
	for _, f := range files {
		if entry, err := decodeObject(f); err == nil {
			out[entryID(entry)] = f
		}
	}
	return out
}

func entryDepth(entry map[string]json.RawMessage) int {
	if d, ok := intField(entry, "depth"); ok {
		return d
	}
	d, _ := intField(entry, "dp")
	return d
}

func entryID(entry map[string]json.RawMessage) int {
	id, _ := intField(entry, "id")
	return id
}

// entrySHA returns a file entry's content SHA-256, or "" when absent.
func entrySHA(entry map[string]json.RawMessage) string {
	var s string
	if v, ok := entry["sha"]; ok {
		_ = json.Unmarshal(v, &s) //nolint:errcheck // non-string → empty, handled by callers
	}
	return s
}

func intField(entry map[string]json.RawMessage, key string) (int, bool) {
	v, ok := entry[key]
	if !ok {
		return 0, false
	}
	var n int
	if json.Unmarshal(v, &n) != nil {
		return 0, false
	}
	return n, true
}

func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// mustMarshal marshals values that are already valid json.RawMessage trees, so
// the only possible error is an unsupported type the callers never construct.
func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("hopper: marshal json tree: %v", err)) // unreachable for RawMessage trees
	}
	return b
}
