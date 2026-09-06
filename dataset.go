package hopper

import (
	"context"
	"strings"
)

// Dataset registry metadata — see cmd/hopper/datasetmeta.go for the layout.
//
// A curated corpus laid out as datasets/<…>/samples/<registry>/<name>/<version>/
// keeps each artifact next to the registry document it was published with.
// The walk turns those documents into the artifact's provenance sidecar; the
// helpers here are the repair side, for rows written before it learned to.

// DatasetMetadataNames are the per-artifact registry documents a dataset
// directory may hold beside the artifact. They are provenance, never samples.
var DatasetMetadataNames = []string{"meta.json.zst", "metadata.json", "maintainers.json"}

// datasetTreeLike matches a stored path inside a dataset's samples tree.
const datasetTreeLike = `path LIKE '%datasets/%/samples/%'`

// datasetMetadataNameList is the SQL IN-list of DatasetMetadataNames.
func datasetMetadataNameList() string {
	quoted := make([]string, len(DatasetMetadataNames))
	for i, n := range DatasetMetadataNames {
		quoted[i] = "'" + n + "'"
	}
	return strings.Join(quoted, ",")
}

// datasetMetadataStagePredicate selects the rows a walk minted from dataset
// registry documents before it knew to skip them: the documents themselves
// (top-level rows named like one, inside a dataset tree) and the members
// exploded out of them, matched by their own path — "<doc>!<member>" — rather
// than through the parent row, so the delete does not depend on the order the
// two are removed in.
func datasetMetadataStagePredicate() string {
	members := make([]string, len(DatasetMetadataNames))
	for i, n := range DatasetMetadataNames {
		members[i] = `path LIKE '%/` + n + `!%'`
	}
	return datasetTreeLike + ` AND ((parent = '' AND filename IN (` + datasetMetadataNameList() + `)) OR ` +
		strings.Join(members, " OR ") + `)`
}

// DatasetArtifactsWithoutProvenance pages, in id order after afterID, the
// top-level samples inside a dataset tree under pathPrefix that carry no
// provenance — the rows a backfill should try to pair with the registry
// document beside them on disk. The documents themselves are excluded.
func (db *DB) DatasetArtifactsWithoutProvenance(ctx context.Context, pathPrefix string, afterID int64, limit int) ([]*Sample, error) {
	if db.pool != nil {
		return db.datasetArtifactsWithoutProvenancePG(ctx, pathPrefix, afterID, limit)
	}
	return db.datasetArtifactsWithoutProvenanceSQLite(ctx, pathPrefix, afterID, limit)
}

// CleanupRow identifies one row a cleanup stage would delete.
type CleanupRow struct {
	SHA256 string
	Path   string
	ID     int64
}

// CleanupRows pages, in id order after afterID, the rows stage matches — what
// [DB.ApplyCleanup] would delete — so an operator can see the list before
// committing to it, not just the count.
func (db *DB) CleanupRows(ctx context.Context, stage CleanupStage, afterID int64, limit int) ([]CleanupRow, error) {
	if db.pool != nil {
		return db.cleanupRowsPG(ctx, stage, afterID, limit)
	}
	return db.cleanupRowsSQLite(ctx, stage, afterID, limit)
}

// AdoptProvenance writes s.Provenance onto the existing row and adopts every
// non-empty scalar claim on s (ecosystem, package, version, purl_base, url,
// domain, feed, fetched_at) over whatever the row holds. It is the repair
// counterpart of the walk's first-sidecar-wins upsert rule: the row's current
// identity is a filename guess ("forge") and the sidecar knows better
// ("@servicetitan/forge"). [DB.SetProvenance] is the conservative sibling that
// only fills blanks. Reports whether a row matched.
func (db *DB) AdoptProvenance(ctx context.Context, s *Sample) (bool, error) {
	var ok bool
	var err error
	if db.pool != nil {
		ok, err = db.adoptProvenancePG(ctx, s)
	} else {
		ok, err = db.adoptProvenanceSQLite(ctx, s)
	}
	if err == nil {
		db.forgetSample(s)
	}
	return ok, err
}
