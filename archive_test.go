package hopper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

// The contract of Split/Join is one law: Join(Split(env)) reproduces env, member
// for member, section for section. These tests assert it semantically — parsed
// JSON deep-equality, independent of key order or formatting — over real and
// synthetic envelopes, plus the dedup and llm-preservation properties that
// motivate the design.

// roundTrip splits an envelope, rebuilds a lookup from the resulting leaves, and
// joins it back. It returns the leaves so tests can assert dedup properties.
func roundTrip(t *testing.T, envelope []byte) (rejoined []byte, leaves []Leaf) {
	t.Helper()
	parent, leaves, err := Split(envelope)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	byID := make(map[string][]byte, len(leaves))
	for _, lf := range leaves {
		byID[lf.SHA256] = lf.Envelope
	}
	rejoined, err = Join(parent, func(sha string) ([]byte, bool) {
		env, ok := byID[sha]
		return env, ok
	})
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	return rejoined, leaves
}

func assertJSONEqual(t *testing.T, want, got []byte) {
	t.Helper()
	if !jsonEqual(want, got) {
		t.Errorf("round-trip diverged\n--- want ---\n%s\n--- got ---\n%s", indentJSON(want), indentJSON(got))
	}
}

// TestRoundTripGoldenArchive runs the law over a real scanner envelope (a Python
// wheel with 13 members, one carrying notable findings). This is the case the
// old finding-blind compaction lost: the member with findings must survive the
// split and come back identical.
func TestRoundTripGoldenArchive(t *testing.T) {
	envelope, err := os.ReadFile("testdata/archive_whl.json")
	if err != nil {
		t.Skipf("golden fixture unavailable: %v", err)
	}

	parent, leaves, err := Split(envelope)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(leaves) != 13 {
		t.Fatalf("want 13 member leaves, got %d", len(leaves))
	}
	// The parent must no longer carry any member's heavy analysis.
	if n := membersWithHeavyPayload(t, parent); n != 0 {
		t.Errorf("parent still holds heavy analysis for %d members; split should reference them", n)
	}

	rejoined, _ := roundTrip(t, envelope)
	assertJSONEqual(t, envelope, rejoined)
}

// TestRoundTripFlatArchive covers a hand-built two-member archive with an llm
// section, asserting both the round-trip and that llm survives reassembly.
func TestRoundTripFlatArchive(t *testing.T) {
	envelope := []byte(`{
		"ml": {"v": "8", "prob": 0.9, "files": [
			{"id": 0, "type": "zip", "prob": 0.9},
			{"id": 1, "type": "python", "prob": 0.8},
			{"id": 2, "type": "python", "prob": 0.1}
		]},
		"llm": {"outcome": "hostile", "interpretation": "imports base64; writes sys.modules", "review": false},
		"raw": {"v": 8, "rev": "abc123", "files": [
			{"id": 0, "sha": "aaa", "path": "pkg.zip", "type": "zip", "size": 900, "risk": 3},
			{"id": 1, "sha": "bbb", "path": "pkg.zip!!a/util.py", "type": "python", "dp": 1, "size": 400, "risk": 3,
			 "traits": [{"id": "x/eval", "crit": 3}], "ctx": [{"ln": 1, "b": "abc"}]},
			{"id": 2, "sha": "ccc", "path": "pkg.zip!!a/empty.py", "type": "python", "dp": 1, "size": 0, "risk": 0}
		]}
	}`)

	rejoined, leaves := roundTrip(t, envelope)
	assertJSONEqual(t, envelope, rejoined)

	if len(leaves) != 2 {
		t.Fatalf("want 2 leaves, got %d", len(leaves))
	}
	// llm is a whole-sample property: it stays on the parent, never on a leaf.
	parent, _, err := Split(envelope)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if !hasTopLevelKey(t, parent, "llm") {
		t.Error("parent lost its llm section")
	}
	for _, lf := range leaves {
		if hasTopLevelKey(t, lf.Envelope, "llm") {
			t.Errorf("leaf %s carries an llm section; interpretation is per-sample, not per-member", lf.SHA256)
		}
	}
}

// TestRoundTripNestedArchive covers depth>1: an archive containing an archive.
// Cleave flattens nesting into one files list with depth markers, so every
// depth>0 entry — at any level — is a referenced member.
func TestRoundTripNestedArchive(t *testing.T) {
	envelope := []byte(`{
		"raw": {"v": 8, "files": [
			{"id": 0, "sha": "outer", "path": "o.tar", "type": "tar", "dp": 0},
			{"id": 1, "sha": "inner", "path": "o.tar!!inner.zip", "type": "zip", "dp": 1, "traits": [{"id": "t", "crit": 1}]},
			{"id": 2, "sha": "leaf", "path": "o.tar!!inner.zip!!run.sh", "type": "shell", "dp": 2, "ctx": [{"ln": 3, "b": "z"}]}
		]}
	}`)
	rejoined, leaves := roundTrip(t, envelope)
	assertJSONEqual(t, envelope, rejoined)
	if len(leaves) != 2 {
		t.Fatalf("want 2 leaves (depth 1 and depth 2), got %d", len(leaves))
	}
}

// TestRoundTripNullBytes asserts the logical law is independent of NUL bytes in
// the content — NUL handling is a storage-column concern (see the codec), not a
// Split/Join concern, so the structure must round-trip with them present.
func TestRoundTripNullBytes(t *testing.T) {
	envelope := []byte("{\"raw\":{\"files\":[" +
		"{\"id\":0,\"sha\":\"aaa\",\"type\":\"bin\",\"dp\":0}," +
		"{\"id\":1,\"sha\":\"bbb\",\"path\":\"a!!x\",\"type\":\"bin\",\"dp\":1,\"traits\":[{\"id\":\"t\",\"d\":\"has \\u0000 byte\"}]}" +
		"]}}")
	rejoined, _ := roundTrip(t, envelope)
	assertJSONEqual(t, envelope, rejoined)
}

// TestSplitDedupsIdenticalMembers asserts the dedup property: the same content
// in two archives produces the same leaf SHA-256 and identical leaf bytes, so
// storage stores it once.
func TestSplitDedupsIdenticalMembers(t *testing.T) {
	member := `{"id":1,"sha":"shared","path":"%s","type":"python","dp":1,"traits":[{"id":"t","crit":2}]}`
	mk := func(path string) []byte {
		return []byte(`{"raw":{"files":[` +
			`{"id":0,"sha":"top","type":"zip","dp":0},` +
			fmt.Sprintf(member, path) + `]}}`)
	}
	_, a, err := Split(mk("archiveA.zip!!pkg/shared.py"))
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := Split(mk("archiveB.zip!!other/shared.py"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want one leaf each, got %d and %d", len(a), len(b))
	}
	if a[0].SHA256 != b[0].SHA256 {
		t.Fatalf("same content keyed differently: %q vs %q", a[0].SHA256, b[0].SHA256)
	}
	// Placement (the differing path) lives on the parent reference, not the leaf,
	// so the leaf bytes are identical and dedup to one stored row.
	if !jsonEqual(a[0].Envelope, b[0].Envelope) {
		t.Errorf("identical content produced different leaves; placement leaked into the leaf\nA: %s\nB: %s",
			a[0].Envelope, b[0].Envelope)
	}
}

// TestSplitNonArchive leaves a single-file envelope (a leaf, or any non-archive)
// untouched, with no members factored out.
func TestSplitNonArchive(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
	}{
		{"single_file", `{"ml":{"v":"8"},"raw":{"files":[{"id":0,"sha":"aaa","type":"python","dp":0,"traits":[{"id":"t","crit":2}]}]}}`},
		{"no_files", `{"ml":{"v":"8","prob":0.1},"raw":{"v":8}}`},
		{"empty_object", `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, leaves, err := Split([]byte(tc.env))
			if err != nil {
				t.Fatalf("Split: %v", err)
			}
			if len(leaves) != 0 {
				t.Errorf("want no leaves for non-archive, got %d", len(leaves))
			}
			assertJSONEqual(t, []byte(tc.env), parent)
			rejoined, _ := roundTrip(t, []byte(tc.env))
			assertJSONEqual(t, []byte(tc.env), rejoined)
		})
	}
}

// TestJoinMissingLeafKeepsReference confirms graceful degradation: when a
// member's leaf can't be fetched, Join leaves the reference in place rather than
// dropping the member or erroring.
func TestJoinMissingLeafKeepsReference(t *testing.T) {
	envelope := []byte(`{"raw":{"files":[` +
		`{"id":0,"sha":"top","type":"zip","dp":0},` +
		`{"id":1,"sha":"bbb","path":"a!!x.py","type":"python","dp":1,"traits":[{"id":"t","crit":3}]}` +
		`]}}`)
	parent, _, err := Split(envelope)
	if err != nil {
		t.Fatal(err)
	}
	// Lookup that never resolves.
	rejoined, err := Join(parent, func(string) ([]byte, bool) { return nil, false })
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	// The member is still present as its reference (placement + identity), just
	// without the heavy payload.
	if membersWithHeavyPayload(t, rejoined) != 0 {
		t.Error("unexpected heavy payload restored without a leaf")
	}
	if got := memberCount(t, rejoined); got != 2 {
		t.Errorf("want 2 files retained (container + stub), got %d", got)
	}
}

// TestReassembleFromColumns exercises the storage round-trip the way hopper
// actually uses it: Split the envelope, store the parent and each leaf as the
// columns of a Sample, then Reassemble from those Samples. The result must equal
// the original — proving Envelope (column↔envelope) composes with Join, and that
// hopper owns the whole read-side reassembly.
func TestReassembleFromColumns(t *testing.T) {
	envelope, err := os.ReadFile("testdata/archive_whl.json")
	if err != nil {
		t.Skipf("golden fixture unavailable: %v", err)
	}
	parentEnv, leaves, err := Split(envelope)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	parent := &Sample{
		CleaveResult: sectionRaw(t, parentEnv, "raw"),
		LitmusResult: sectionRaw(t, parentEnv, "ml"),
		LLMResult:    sectionRaw(t, parentEnv, "llm"),
	}
	members := make([]*Sample, 0, len(leaves))
	for _, lf := range leaves {
		members = append(members, &Sample{
			SHA256:       lf.SHA256,
			CleaveResult: sectionRaw(t, lf.Envelope, "raw"),
			LitmusResult: sectionRaw(t, lf.Envelope, "ml"),
		})
	}

	rejoined, err := Reassemble(parent, members)
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	assertJSONEqual(t, envelope, rejoined)
}

// TestReassembleNonArchive returns a standalone sample's own envelope unchanged.
func TestReassembleNonArchive(t *testing.T) {
	s := &Sample{
		LitmusResult: []byte(`{"v":"8","prob":0.2}`),
		CleaveResult: []byte(`{"files":[{"id":0,"sha":"aaa","type":"python","dp":0,"traits":[{"id":"t","crit":2}]}]}`),
	}
	got, err := Reassemble(s, nil)
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	assertJSONEqual(t, Envelope(s), got)
}

// TestStorageRoundTrip exercises the real write→read path end to end: compact
// the parent cleave result the way UpdateCleaveResult does, build member rows the
// way ExplodeArchiveMembers does, then Reassemble. The result must equal the
// original envelope — proving compaction (Split) and the explosion format
// compose with Reassemble (Join) to the identity the design promises.
func TestStorageRoundTrip(t *testing.T) {
	envelope, err := os.ReadFile("testdata/archive_whl.json")
	if err != nil {
		t.Skipf("golden fixture unavailable: %v", err)
	}
	top := mustDecode(t, envelope)
	raw, err := section(top, "raw")
	if err != nil {
		t.Fatal(err)
	}

	// Write path: the parent stores the compacted cleave; each member becomes its
	// own row carrying its single-file cleave and per-member litmus verdict.
	parent := &Sample{
		CleaveResult: compactCleaveResultForStorage(top["raw"]),
		LitmusResult: top["ml"],
		LLMResult:    top["llm"],
	}
	var members []*Sample
	for _, e := range raw.files {
		entry, derr := decodeObject(e)
		if derr != nil || entryDepth(entry) == 0 {
			continue
		}
		members = append(members, &Sample{
			SHA256:       entrySHA(entry),
			CleaveResult: mustMarshal(map[string]json.RawMessage{"files": mustMarshal([]json.RawMessage{e})}),
			LitmusResult: litmusResultForMember(top["ml"], entryID(entry)),
		})
	}

	rejoined, err := Reassemble(parent, members)
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	assertJSONEqual(t, envelope, rejoined)
}

// TestReassembleClearsMarkers confirms Reassemble drops the storage-time
// "truncated" flag once it has reassembled (so a reader never re-reassembles a
// finished envelope) and reports any members left as references in
// "omitted_files".
func TestReassembleClearsMarkers(t *testing.T) {
	parent := &Sample{CleaveResult: []byte(`{"truncated":true,"omitted_files":2,"files":[` +
		`{"id":0,"sha":"top","type":"zip","dp":0},` +
		`{"id":1,"sha":"bbb","path":"a!!x.py","type":"python","dp":1},` +
		`{"id":2,"sha":"ccc","path":"a!!y.py","type":"python","dp":1}` +
		`]}`)}
	member := &Sample{SHA256: "bbb", CleaveResult: []byte(`{"files":[{"sha":"bbb","type":"python","traits":[{"id":"t","crit":3}]}]}`)}

	got, err := Reassemble(parent, []*Sample{member})
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}
	raw, err := section(mustDecode(t, got), "raw")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.obj["truncated"]; ok {
		t.Error("truncated marker survived reassembly")
	}
	// One member (ccc) had no leaf, so it stays a reference and is counted.
	var omitted int
	if err := json.Unmarshal(raw.obj["omitted_files"], &omitted); err != nil || omitted != 1 {
		t.Errorf("omitted_files = %s (err %v), want 1", raw.obj["omitted_files"], err)
	}
}

// --- helpers ---

func mustDecode(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	obj, err := decodeObject(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return obj
}

// sectionRaw returns the raw bytes of a top-level envelope key, or nil when
// absent — mirroring how a result's sections land in separate Sample columns.
func sectionRaw(t *testing.T, envelope []byte, key string) []byte {
	t.Helper()
	obj, err := decodeObject(envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return obj[key]
}

func jsonEqual(a, b []byte) bool {
	return reflect.DeepEqual(decodeAny(a), decodeAny(b))
}

func decodeAny(b []byte) any {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // compare 5 and 5.0 distinctly; preserve large ints
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(b) // unparseable: fall back to raw, surfaces as inequality
	}
	return v
}

func indentJSON(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return string(b)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(b)
	}
	return string(out)
}

func hasTopLevelKey(t *testing.T, envelope []byte, key string) bool {
	t.Helper()
	obj, err := decodeObject(envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	_, ok := obj[key]
	return ok
}

// membersWithHeavyPayload counts raw.files entries that still carry per-file
// analysis (ctx/traits/find/facts) — the fields Split is supposed to factor out.
func membersWithHeavyPayload(t *testing.T, envelope []byte) int {
	t.Helper()
	files := rawFiles(t, envelope)
	heavy := []string{"ctx", "traits", "find", "ts", "facts", "fact"}
	n := 0
	for _, f := range files {
		entry, err := decodeObject(f)
		if err != nil {
			t.Fatalf("decode entry: %v", err)
		}
		if entryDepth(entry) == 0 {
			continue // container keeps its payload
		}
		for _, k := range heavy {
			if _, ok := entry[k]; ok {
				n++
				break
			}
		}
	}
	return n
}

func memberCount(t *testing.T, envelope []byte) int {
	t.Helper()
	return len(rawFiles(t, envelope))
}

func rawFiles(t *testing.T, envelope []byte) []json.RawMessage {
	t.Helper()
	top, err := decodeObject(envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	raw, err := section(top, "raw")
	if err != nil {
		t.Fatalf("section raw: %v", err)
	}
	return raw.files
}

// TestSplitParentOnlyMatchesSplit locks the storage-compaction invariant:
// splitParentOnly must produce a parent byte-identical to Split's, and report
// the same member count, while skipping the leaf assembly that dominated the
// heap. If these ever diverge, compacted cleave_result bytes would change.
func TestSplitParentOnlyMatchesSplit(t *testing.T) {
	cases := map[string][]byte{
		"flat": []byte(`{
			"ml": {"v": "8", "files": [
				{"id": 0, "type": "zip"},
				{"id": 1, "type": "python"},
				{"id": 2, "type": "python"}
			]},
			"raw": {"v": 8, "rev": "abc123", "files": [
				{"id": 0, "sha": "aaa", "path": "pkg.zip", "type": "zip", "size": 900, "risk": 3},
				{"id": 1, "sha": "bbb", "path": "pkg.zip!!a/util.py", "type": "python", "dp": 1, "size": 400, "risk": 3,
				 "traits": [{"id": "x/eval", "crit": 3}], "ctx": [{"ln": 1, "b": "abc"}]},
				{"id": 2, "sha": "ccc", "path": "pkg.zip!!a/empty.py", "type": "python", "dp": 1, "size": 0, "risk": 0}
			]}
		}`),
		"non-archive": []byte(`{"raw": {"v": 8, "files": [
			{"id": 0, "sha": "aaa", "path": "lone.py", "type": "python"}
		]}}`),
	}
	if golden, err := os.ReadFile("testdata/archive_whl.json"); err == nil {
		cases["golden"] = golden
	}

	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			wantParent, leaves, err := Split(envelope)
			if err != nil {
				t.Fatalf("Split: %v", err)
			}
			gotParent, members, err := splitParentOnly(envelope)
			if err != nil {
				t.Fatalf("splitParentOnly: %v", err)
			}
			if members != len(leaves) {
				t.Errorf("members = %d, want %d (len leaves)", members, len(leaves))
			}
			if !bytes.Equal(wantParent, gotParent) {
				t.Errorf("parent diverged\n--- Split ---\n%s\n--- splitParentOnly ---\n%s",
					indentJSON(wantParent), indentJSON(gotParent))
			}
		})
	}
}
