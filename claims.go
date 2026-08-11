package hopper

// Identity claims: who says these bytes are what.
//
// Every claim about a file's identity is one immutable row in the claims
// table — the analyzer's per-file `ident` block (a PE version resource, a
// bundle manifest, a code signature) projected into queryable columns at
// StoreResult time. Registry claims are NOT stored here: they already live on
// samples (package/version/purl_base, indexed), and the asset_claims view
// unions the two so "all versions of X" is one query regardless of where the
// claim came from. Disagreement between claims is data — an unsigned exe
// claiming a popular name coexists with the registry rows for that name, and
// that coexistence is the supply-chain signal.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// Claim is one identity assertion about a sample's bytes, extracted from the
// analyzer envelope. Source is the asserting mechanism as filefacts recorded
// it (e.g. "pe.version.original_filename"); the reserved source "registry" is
// emitted only by the asset_claims view, never stored.
type Claim struct {
	SHA256   string
	Source   string
	Name     string
	Version  string
	Signer   string
	Trust    string
	Verified bool
}

// claimIdent is the subset of a per-file `ident` block claims are built from.
type claimIdent struct {
	Signer struct {
		Organization string `json:"organization"`
		CommonName   string `json:"common_name"`
	} `json:"signer"`
	Version struct {
		Value string `json:"value"`
	} `json:"version"`
	Trust string `json:"trust"`
	Name  struct {
		Value    string `json:"value"`
		Source   string `json:"source"`
		Verified bool   `json:"verified"`
	} `json:"name"`
}

// ClaimsFromEnvelope extracts one claim per envelope file whose analyzer
// ident names the file. Files without an ident, without a name claim, or
// without a valid sha are skipped — an identity that can't be grouped by name
// has nothing to contribute. Duplicate (sha256, source) pairs within one
// envelope collapse to the first occurrence, matching the table's key.
func ClaimsFromEnvelope(cleaveResult []byte) []Claim {
	if len(cleaveResult) == 0 {
		return nil
	}
	var report struct {
		Files    []json.RawMessage `json:"files"`
		OldFiles []json.RawMessage `json:"fs"`
	}
	if json.Unmarshal(cleaveResult, &report) != nil {
		return nil
	}
	files := report.Files
	if len(files) == 0 {
		files = report.OldFiles
	}

	var claims []Claim
	seen := make(map[[2]string]bool)
	for _, raw := range files {
		var entry struct {
			Ident *claimIdent `json:"ident"`
			SHA   string      `json:"sha"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.Ident == nil {
			continue
		}
		ident := entry.Ident
		if ident.Name.Value == "" || ident.Name.Source == "" {
			continue
		}
		sha := strings.ToLower(entry.SHA)
		if !isLowerHexSHA256(sha) {
			continue
		}
		key := [2]string{sha, ident.Name.Source}
		if seen[key] {
			continue
		}
		seen[key] = true
		signer := ident.Signer.Organization
		if signer == "" {
			signer = ident.Signer.CommonName
		}
		claims = append(claims, Claim{
			SHA256:   sha,
			Source:   ident.Name.Source,
			Name:     ident.Name.Value,
			Version:  ident.Version.Value,
			Signer:   signer,
			Verified: ident.Name.Verified,
			Trust:    ident.Trust,
		})
	}
	return claims
}

// identEnvelopeVersion is the first envelope generation whose per-file
// entries carry the `ident` identity block. Rows analyzed by older
// generations have nothing to project and need re-analysis; rows at or past
// it are ground truth — a v8 row without idents genuinely has none.
const identEnvelopeVersion = 8

// envelopeVersionSQL reads the envelope generation as an integer, 0 for
// missing/pre-versioned envelopes. `v` is a small top-level key, so this is
// far cheaper than a jsonpath scan across every per-file entry.
const envelopeVersionSQL = `coalesce(nullif(cleave_result->>'v', '')::int, 0)`

// BackfillClaims projects claims out of stored envelopes that already carry
// identity blocks (generation >= identEnvelopeVersion) — the
// direct-extraction lane for rows analyzed after v8 shipped but before the
// claims table existed, and the completeness sweeper after a rescan wave.
// Walks every row (members carry their own single-file slices), batched by
// id cursor, resumable via startID, and idempotent: the upsert is
// delta-guarded, so a second run over the same rows writes nothing.
// Postgres-only, like CanonicalizePURLBases.
func (db *DB) BackfillClaims(ctx context.Context, startID int64) (rows, claims int64, err error) {
	if db.pool == nil {
		return 0, 0, errors.New("hopper: backfill-claims requires postgres")
	}
	const batch = 2000
	cursor := startID
	for {
		res, err := db.pool.Query(ctx, `
			SELECT id, cleave_result FROM samples
			 WHERE id > $1 AND cleave_result IS NOT NULL
			   AND `+envelopeVersionSQL+` >= `+strconv.Itoa(identEnvelopeVersion)+`
			 ORDER BY id LIMIT $2`, cursor, batch)
		if err != nil {
			return rows, claims, fmt.Errorf("hopper: backfill claims scan: %w", err)
		}
		var pending []Claim
		n := 0
		for res.Next() {
			var id int64
			var envelope []byte
			if err := res.Scan(&id, &envelope); err != nil {
				res.Close()
				return rows, claims, fmt.Errorf("hopper: backfill claims scan: %w", err)
			}
			cursor, n = id, n+1
			pending = append(pending, ClaimsFromEnvelope(envelope)...)
		}
		if err := res.Err(); err != nil {
			return rows, claims, fmt.Errorf("hopper: backfill claims scan: %w", err)
		}
		if err := db.storeClaimsPG(ctx, pending); err != nil {
			return rows, claims, err
		}
		rows += int64(n)
		claims += int64(len(pending))
		if n < batch {
			return rows, claims, nil
		}
		slog.Info("backfill-claims progress", "cursor", cursor, "rows", rows, "claims", claims)
	}
}

// QueuePreIdentForRepair flags analyzed, active, top-level samples whose
// stored envelope predates the identity block for the repair-tier rescan
// (rescan_priority=1, drained behind new ingestion — the same tier the
// missing-members repair uses). Re-analysis under a current build stores a
// v8 envelope and StoreResult projects its claims, so no second pass is
// needed. fileTypes narrows the sweep for a tiered rollout ('pe','macho',…);
// empty sweeps every type. dryRun counts without flagging. Batched by id
// cursor so no statement locks more than one batch; idempotent — flagged
// rows fail the rescan_priority=0 predicate on a re-run. Postgres-only.
func (db *DB) QueuePreIdentForRepair(ctx context.Context, fileTypes []string, dryRun bool) (int64, error) {
	if db.pool == nil {
		return 0, errors.New("hopper: pre-ident rescan requires postgres")
	}
	if dryRun {
		var n int64
		err := db.pool.QueryRow(ctx, `
			SELECT count(*) FROM samples
			 WHERE parent = '' AND skip = '' AND rescan_priority = 0
			   AND cleave_result IS NOT NULL
			   AND `+envelopeVersionSQL+` < `+strconv.Itoa(identEnvelopeVersion)+`
			   AND (coalesce(cardinality($1::text[]), 0) = 0 OR file_type = ANY($1))`,
			fileTypes).Scan(&n)
		if err != nil {
			return 0, fmt.Errorf("hopper: pre-ident count: %w", err)
		}
		return n, nil
	}
	const batch = 20000
	var total int64
	var cursor int64
	for {
		var n int64
		var next *int64
		err := db.pool.QueryRow(ctx, `
			WITH batch AS (
				SELECT id FROM samples
				 WHERE id > $1 AND parent = '' AND skip = '' AND rescan_priority = 0
				   AND cleave_result IS NOT NULL
				   AND `+envelopeVersionSQL+` < `+strconv.Itoa(identEnvelopeVersion)+`
				   AND (coalesce(cardinality($2::text[]), 0) = 0 OR file_type = ANY($2))
				 ORDER BY id LIMIT $3
			), flagged AS (
				UPDATE samples s
				   SET rescan_priority = 1,
				       rescan_requested_at = COALESCE(rescan_requested_at, now())
				  FROM batch b WHERE s.id = b.id
			)
			SELECT count(*), max(id) FROM batch`, cursor, fileTypes, batch).Scan(&n, &next)
		if err != nil {
			return total, fmt.Errorf("hopper: pre-ident rescan batch: %w", err)
		}
		total += n
		if n < batch || next == nil {
			return total, nil
		}
		cursor = *next
		slog.Info("pre-ident rescan progress", "cursor", cursor, "flagged", total)
	}
}
