package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
)

// refreshSidecar builds an upload sidecar whose registry snapshot is tagged with
// source, so a test can tell which of two sidecars a refresh actually stored.
func refreshSidecar(sha string, size int, source string) *hopper.Sidecar {
	return &hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      hopper.Artifact{Filename: "foo-1.0.0.tgz", SHA256: sha, SizeBytes: int64(size)},
		Package:       hopper.PackageRef{Ecosystem: "npm", Name: "foo", Version: "1.0.0", PURL: "pkg:npm/foo@1.0.0", Feed: "npm"},
		Fetch:         hopper.Fetch{Collector: "scan+host", Category: "new", At: time.Now().UTC(), URL: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"},
		Registry: &hopper.MetadataRecord{
			SourceID: source, Format: "npm.packument", URL: "https://registry.npmjs.org/foo",
			Status: hopper.MetadataComplete, Record: json.RawMessage(`{"tag":"` + source + `"}`),
		},
	}
}

// storedRegistrySource returns the registry source_id of the sidecar hopper
// currently holds for sha, so a refresh can be checked by which snapshot won.
func storedRegistrySource(t *testing.T, api *apiServer, sha string) string {
	t.Helper()
	raw, err := api.db.ProvenanceBySHA256(context.Background(), sha)
	if err != nil {
		t.Fatalf("ProvenanceBySHA256: %v", err)
	}
	var got hopper.Sidecar
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal stored sidecar: %v", err)
	}
	if got.Registry == nil {
		t.Fatal("stored sidecar carries no registry record")
	}
	return got.Registry.SourceID
}

// TestProvenanceBackfillUnknownSampleIs404 pins the status for a backfill that
// stored nothing. A 200 here told the producer its metadata had landed when no
// row existed to attach it to, and scan's client — which only checks
// status().is_success() — logged the no-op as a success.
func TestProvenanceBackfillUnknownSampleIs404(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	sum := sha256.Sum256([]byte("bytes hopper has never seen"))
	sha := hex.EncodeToString(sum[:])

	body, ct := provenanceOnlyUpload(t, mustJSON(t, refreshSidecar(sha, 27, "npm-new")))
	w := postUpload(t, api, body, ct)

	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d, want %d (nothing was stored)", w.Code, http.StatusNotFound)
	}
	if _, err := api.db.ProvenanceBySHA256(context.Background(), sha); err == nil {
		t.Error("provenance stored for a sample hopper has no row for")
	}
}

// TestUploadWithBytesRefreshesProvenance covers a sidecar arriving alongside
// bytes hopper already holds. The sample upsert keeps a stored sidecar — right
// for the walker, wrong for a producer sending a newer registry snapshot — so
// the refresh has to happen explicitly. Before it did, the newer metadata was
// silently discarded behind an "upload accepted" 200, and the same sidecar sent
// without bytes had the opposite effect.
func TestUploadWithBytesRefreshesProvenance(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	file := []byte("dependency tarball bytes")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	body, ct := multipartUpload(t, mustJSON(t, refreshSidecar(sha, len(file), "npm-old")), file, true)
	w := postUpload(t, api, body, ct)
	if w.Code != http.StatusOK {
		t.Fatalf("initial upload: code=%d body=%s", w.Code, w.Body.String())
	}
	var first uploadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode initial response: %v", err)
	}
	if !first.ProvenanceApplied {
		t.Error("provenance_applied = false on a first store that wrote the sidecar")
	}

	// Same bytes, newer registry snapshot.
	body2, ct2 := multipartUpload(t, mustJSON(t, refreshSidecar(sha, len(file), "npm-new")), file, true)
	w2 := postUpload(t, api, body2, ct2)
	if w2.Code != http.StatusOK {
		t.Fatalf("re-upload: code=%d body=%s", w2.Code, w2.Body.String())
	}
	var second uploadResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode re-upload response: %v", err)
	}
	if !second.ProvenanceApplied {
		t.Error("provenance_applied = false, want true — the newer sidecar was accepted")
	}
	if got := storedRegistrySource(t, api, sha); got != "npm-new" {
		t.Errorf("stored registry source_id = %q, want %q — the newer sidecar was dropped", got, "npm-new")
	}
}

// TestUploadRefreshesRowFromAnotherWriter covers an upload landing on a row some
// other producer created first — the common shape when forager and a scan worker
// reach the same artifact. The newer snapshot must win and the reported flag must
// match what was stored.
//
// Note this does not discriminate the handler's own failed-lookup case, where it
// warns and continues with no existing row for one that exists: reaching that
// needs a fault-injection seam the concrete *hopper.DB does not offer. The
// defense there is structural rather than pinned here — provenance_applied is
// read back from the write instead of inferred from the lookup, so there is no
// inference left to be wrong.
func TestUploadRefreshesRowFromAnotherWriter(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	file := []byte("bytes another producer inserted first")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	// Another writer lands the row (with an older snapshot) first.
	seeded := uploadSample(sha, "foo-1.0.0.tgz", "unknown/uploads/seeded.tgz",
		int64(len(file)), refreshSidecar(sha, len(file), "npm-old"))
	if err := api.db.InsertSample(context.Background(), seeded); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	body, ct := multipartUpload(t, mustJSON(t, refreshSidecar(sha, len(file), "npm-new")), file, true)
	w := postUpload(t, api, body, ct)
	if w.Code != http.StatusOK {
		t.Fatalf("upload: code=%d body=%s", w.Code, w.Body.String())
	}
	var got uploadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.ProvenanceApplied {
		t.Error("provenance_applied = false, want true — a row matched and was refreshed")
	}
	if src := storedRegistrySource(t, api, sha); src != "npm-new" {
		t.Errorf("stored registry source_id = %q, want %q", src, "npm-new")
	}
}

// TestUploadAdoptsDiscoveryFeedFromLaterProducer is what the refresh buys in
// production. forager and a scan worker reach the same artifact independently,
// and only forager's sidecar carries the discovery Feed — how the package was
// first seen. forager skips bytes for a sha hopper already holds, so this fires
// when its /api/known probe and its upload straddle another producer's insert:
// it sends bytes + a Feed-carrying sidecar for a sha that just became known.
//
// forager has no provenance-only shape (pkg/forager/upload.go always writes both
// a "provenance" and a "file" part), so the bytes path is the only way its Feed
// can ever reach hopper. Dropping the sidecar there lost the discovery record
// outright, with an "upload accepted" 200 over it.
func TestUploadAdoptsDiscoveryFeedFromLaterProducer(t *testing.T) {
	t.Parallel()
	api := uploadAPI(t)
	file := []byte("package both producers found")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	// scan gets there first: a sidecar with a registry snapshot but no Feed.
	scanSide := refreshSidecar(sha, len(file), "npm-old")
	body, ct := multipartUpload(t, mustJSON(t, scanSide), file, true)
	if w := postUpload(t, api, body, ct); w.Code != http.StatusOK {
		t.Fatalf("scan upload: code=%d body=%s", w.Code, w.Body.String())
	}

	// forager follows with the same bytes and the discovery Feed.
	foragerSide := refreshSidecar(sha, len(file), "npm-new")
	foragerSide.Fetch.Collector = "forager+test"
	foragerSide.Feed = &hopper.MetadataRecord{
		SourceID: "npm-firehose", Format: "npm.event",
		URL: "https://npm/feed", Status: hopper.MetadataComplete,
	}
	body2, ct2 := multipartUpload(t, mustJSON(t, foragerSide), file, true)
	if w := postUpload(t, api, body2, ct2); w.Code != http.StatusOK {
		t.Fatalf("forager upload: code=%d body=%s", w.Code, w.Body.String())
	}

	raw, err := api.db.ProvenanceBySHA256(context.Background(), sha)
	if err != nil {
		t.Fatalf("ProvenanceBySHA256: %v", err)
	}
	var got hopper.Sidecar
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal stored sidecar: %v", err)
	}
	if got.Feed == nil {
		t.Fatal("discovery feed dropped: forager's sidecar arrived with bytes and was discarded")
	}
	if got.Feed.SourceID != "npm-firehose" {
		t.Errorf("feed source_id = %q, want %q", got.Feed.SourceID, "npm-firehose")
	}
	if got.Registry.SourceID != "npm-new" {
		t.Errorf("registry source_id = %q, want %q", got.Registry.SourceID, "npm-new")
	}
}

// TestUploadShapesAgreeOnProvenance is the invariant the two shapes kept
// breaking: for bytes hopper already holds, sending the sidecar with the file
// and sending it alone must leave the same sidecar stored. The producer that
// sends more must never accomplish less.
func TestUploadShapesAgreeOnProvenance(t *testing.T) {
	t.Parallel()
	file := []byte("shared dependency bytes")
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])

	// Seed each server identically, then refresh through the two shapes.
	seed := func(t *testing.T) *apiServer {
		t.Helper()
		api := uploadAPI(t)
		body, ct := multipartUpload(t, mustJSON(t, refreshSidecar(sha, len(file), "npm-old")), file, true)
		if w := postUpload(t, api, body, ct); w.Code != http.StatusOK {
			t.Fatalf("seed upload: code=%d body=%s", w.Code, w.Body.String())
		}
		return api
	}

	withBytes := seed(t)
	body, ct := multipartUpload(t, mustJSON(t, refreshSidecar(sha, len(file), "npm-new")), file, true)
	if w := postUpload(t, withBytes, body, ct); w.Code != http.StatusOK {
		t.Fatalf("refresh with bytes: code=%d body=%s", w.Code, w.Body.String())
	}

	sidecarOnly := seed(t)
	body2, ct2 := provenanceOnlyUpload(t, mustJSON(t, refreshSidecar(sha, len(file), "npm-new")))
	if w := postUpload(t, sidecarOnly, body2, ct2); w.Code != http.StatusOK {
		t.Fatalf("refresh without bytes: code=%d body=%s", w.Code, w.Body.String())
	}

	if a, b := storedRegistrySource(t, withBytes, sha), storedRegistrySource(t, sidecarOnly, sha); a != b {
		t.Errorf("upload shapes disagree: with bytes stored %q, sidecar-only stored %q", a, b)
	}
}
