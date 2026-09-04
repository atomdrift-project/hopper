package hopper

import (
	"context"
	"strings"
	"testing"
)

// A v8-shaped envelope: an npm root plus one PE member carrying identity
// claims from its version resource and signer (the shape scan ships since
// envelope v8; see claims.go), and one member with no claims at all.
const identEnvelope = `{"v":"8","files":[
 {"id":0,"sha":"ROOT","type":"npm","path":"pkg.tgz","size":10},
 {"id":1,"sha":"EXE","type":"pe","path":"pkg.tgz!!bin/tool.exe","size":5120,"depth":1,
  "ident":{"name":{"value":"7-Zip","source":"pe.version.product_name","verified":true},
           "version":{"value":"24.08"},
           "trust":"ca_signed",
           "signer":{"organization":"Igor Pavlov"}}},
 {"id":2,"sha":"DOC","type":"markdown","path":"pkg.tgz!!README.md","size":1024,"depth":1}
]}`

func identEnvelopeFor(root, exe, doc string) []byte {
	return []byte(strings.NewReplacer("ROOT", root, "EXE", exe, "DOC", doc).Replace(identEnvelope))
}

func TestClaimsFromEnvelope(t *testing.T) {
	exe := strings.Repeat("b", 64)
	env := identEnvelopeFor(strings.Repeat("a", 64), exe, strings.Repeat("c", 64))
	claims := ClaimsFromEnvelope(env)
	if len(claims) != 1 {
		t.Fatalf("claims = %+v, want exactly the exe's", claims)
	}
	want := Claim{
		SHA256: exe, Source: "pe.version.product_name", Name: "7-Zip",
		Version: "24.08", Signer: "Igor Pavlov", Verified: true, Trust: "ca_signed",
	}
	if claims[0] != want {
		t.Errorf("claim = %+v, want %+v", claims[0], want)
	}
}

// StoreResult projects each analyzer ident into a claims row, and the
// asset_claims view presents it alongside the registry claim already on the
// parent's samples row — the "all versions of X" query surface.
func TestStoreResultProjectsClaims(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	root := strings.Repeat("a", 64)
	exe := strings.Repeat("b", 64)
	mustInsert(t, ctx, db, &Sample{
		SHA256: root, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "unknown/pkg.tgz", FileType: "npm",
		Package: "pkg", Version: "1.0.0", PURLBase: "pkg:npm/pkg", Domain: "npmjs.org",
	})
	env := identEnvelopeFor(root, exe, strings.Repeat("c", 64))
	if _, err := db.StoreResult(ctx, root, env, nil, nil, nil, "tv1"); err != nil {
		t.Fatalf("StoreResult: %v", err)
	}

	var got Claim
	if err := db.lite.QueryRowContext(ctx,
		`SELECT sha256, source, name, version, signer, verified, trust
		   FROM claims WHERE sha256 = ?`, exe).
		Scan(&got.SHA256, &got.Source, &got.Name, &got.Version,
			&got.Signer, &got.Verified, &got.Trust); err != nil {
		t.Fatalf("claim row for exe member: %v", err)
	}
	want := Claim{
		SHA256: exe, Source: "pe.version.product_name", Name: "7-Zip",
		Version: "24.08", Signer: "Igor Pavlov", Verified: true, Trust: "ca_signed",
	}
	if got != want {
		t.Errorf("stored claim = %+v, want %+v", got, want)
	}

	// The view unions the parent's registry identity with the analyzer claim.
	var sources []string
	rows, err := db.lite.QueryContext(ctx,
		`SELECT source FROM asset_claims WHERE sha256 IN (?, ?) ORDER BY source`, root, exe)
	if err != nil {
		t.Fatalf("asset_claims: %v", err)
	}
	defer rows.Close() //nolint:errcheck // test cleanup
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(sources) != 2 || sources[0] != "pe.version.product_name" || sources[1] != "registry" {
		t.Errorf("asset_claims sources = %v, want [pe.version.product_name registry]", sources)
	}

	// The feed's claim filter finds the member by (name, signer) — the
	// version-timeline query — and the registry claim by name alone.
	feed, err := db.FeedSamples(ctx, &FeedQuery{
		Source: SourceExploded, ClaimName: "7-Zip", ClaimSigner: "Igor Pavlov",
	})
	if err != nil {
		t.Fatalf("FeedSamples(claim): %v", err)
	}
	if len(feed) != 1 || feed[0].SHA256 != exe {
		t.Errorf("claim-filtered feed = %d rows, want just the exe", len(feed))
	}
	feed, err = db.FeedSamples(ctx, &FeedQuery{Source: "test", ClaimName: "pkg"})
	if err != nil {
		t.Fatalf("FeedSamples(registry claim): %v", err)
	}
	if len(feed) != 1 || feed[0].SHA256 != root {
		t.Errorf("registry-claim feed = %d rows, want just the parent", len(feed))
	}

	// A walker-parsed FTP-era tarball — filename identity, no purl — surfaces
	// through the view's 'filename' branch and the same feed filter.
	tarball := strings.Repeat("d", 64)
	mustInsert(t, ctx, db, &Sample{
		SHA256: tarball, Source: "test", Label: "unknown", LabelSource: "test",
		Path: "unknown/wuftpd-10.9.2.tgz", FileType: "tar.gz",
		Package: "wuftpd", Version: "10.9.2",
	})
	var src string
	if err := db.lite.QueryRowContext(ctx,
		`SELECT source FROM asset_claims WHERE sha256 = ?`, tarball).Scan(&src); err != nil {
		t.Fatalf("filename-branch claim: %v", err)
	}
	if src != "filename" {
		t.Errorf("tarball claim source = %q, want %q", src, "filename")
	}

	// Re-storing the same envelope is a pure no-op: same one claim row.
	if _, err := db.StoreResult(ctx, root, env, nil, nil, nil, "tv1"); err != nil {
		t.Fatalf("StoreResult(again): %v", err)
	}
	var n int
	if err := db.lite.QueryRowContext(ctx, `SELECT count(*) FROM claims`).Scan(&n); err != nil {
		t.Fatalf("count claims: %v", err)
	}
	if n != 1 {
		t.Errorf("claims rows after re-store = %d, want 1", n)
	}
}
