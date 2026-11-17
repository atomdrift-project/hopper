package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/klauspost/compress/zstd"
)

// FillReports stores reports, by sample id, for files atomscan judged whose
// stored report says no more than their molecule (a molecule and a risk): all
// an archive's report kept of its members once legacy hopper had cut their
// entries out of it. What the stored report says that the new one does not is
// kept. A file with a fuller report (one too long to read, too), or no atomscan
// verdict, is left as it is,
// as is one whose report changed since it was read. It returns how many it
// filled. The migration fills members' reports from the legacy excerpts so.
func (st *Store) FillReports(ctx context.Context, reports map[int64][]byte) (int64, error) {
	if len(reports) == 0 {
		return 0, nil
	}
	ids := slices.Sorted(maps.Keys(reports))
	rows, err := st.pool.Query(ctx, `SELECT sample_id, detail, digest FROM verdicts
		WHERE sample_id = ANY ($1) AND scanner_id = $2`, ids, atomscan)
	if err != nil {
		return 0, fmt.Errorf("store: fill reports: %w", err)
	}
	var (
		fillIDs                []int64
		details, digests, olds [][]byte
	)
	type stored struct {
		detail, digest []byte
		id             int64
	}
	var current []stored
	for rows.Next() {
		var s stored
		if err := rows.Scan(&s.id, &s.detail, &s.digest); err != nil {
			rows.Close()
			return 0, fmt.Errorf("store: fill reports: %w", err)
		}
		current = append(current, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: fill reports: %w", err)
	}
	for _, s := range current {
		report := reports[s.id]
		if len(report) == 0 {
			continue
		}
		if s.detail != nil {
			old, err := st.dec.DecodeAll(s.detail, nil)
			if errors.Is(err, zstd.ErrDecoderSizeExceeded) {
				continue // longer than any line the store takes: no molecule alone
			}
			if err != nil {
				return 0, fmt.Errorf("store: fill report of sample %d: %w", s.id, err)
			}
			merged, ok := underMolecule(old, report)
			if !ok {
				continue
			}
			report = merged
		}
		sum := sha256.Sum256(report)
		fillIDs, olds = append(fillIDs, s.id), append(olds, s.digest)
		details, digests = append(details, st.enc.EncodeAll(report, nil)), append(digests, sum[:])
	}
	if len(fillIDs) == 0 {
		return 0, nil
	}
	tag, err := st.pool.Exec(ctx, `UPDATE verdicts v SET detail = u.detail, digest = u.digest
		FROM unnest($1::bigint[], $2::bytea[], $3::bytea[], $4::bytea[]) AS u (id, detail, digest, old)
		WHERE v.sample_id = u.id AND v.scanner_id = $5 AND v.digest IS NOT DISTINCT FROM u.old`,
		fillIDs, details, digests, olds, atomscan)
	if err != nil {
		return 0, fmt.Errorf("store: fill reports: %w", err)
	}
	return tag.RowsAffected(), nil
}

// underMolecule returns report with what old says that report does not,
// when old says no more than a molecule and a risk; false otherwise, and for
// an old report that is not one JSON object. Keys are sorted, as scan writes
// them.
func underMolecule(old, report []byte) ([]byte, bool) {
	var was, now map[string]json.RawMessage
	if json.Unmarshal(old, &was) != nil || json.Unmarshal(report, &now) != nil {
		return nil, false
	}
	for k := range was {
		if k != "mol" && k != "risk" {
			return nil, false
		}
	}
	for k, v := range was {
		if _, ok := now[k]; !ok {
			now[k] = v
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(now); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), true
}

// Verdict is atomscan's opinion of a file nothing has judged, as the migration
// recovers it from a legacy excerpt (FillVerdicts).
type Verdict struct {
	At      time.Time       // when the opinion was formed
	Opinion json.RawMessage // atomscan's object: outcome, class, fires_at, the strongest findings
	Ruleset string
	Report  []byte // the report line, or nil
	ID      int64  // the sample
}

// FillVerdicts stores atomscan's verdict, and report, for files that have
// none: the opinion of a file legacy hopper analyzed as a member and no scan
// has judged since. A file that already has an atomscan verdict keeps it,
// whatever its age, and a sample that does not exist takes none. The scan
// that does judge the file later replaces what is stored here, which is
// formed at the excerpt's time. It returns how many it stored. No scans row
// is written: the file has not been scanned on its own.
func (st *Store) FillVerdicts(ctx context.Context, verdicts []Verdict) (int64, error) {
	if len(verdicts) == 0 {
		return 0, nil
	}
	var (
		ids              []int64
		opinions         []string
		rulesets         []string
		times            []time.Time
		digests, details [][]byte
	)
	for _, v := range verdicts {
		ids, opinions, rulesets, times = append(ids, v.ID), append(opinions, string(v.Opinion)), append(rulesets, v.Ruleset), append(times, v.At)
		if len(v.Report) == 0 {
			digests, details = append(digests, nil), append(details, nil)
			continue
		}
		sum := sha256.Sum256(v.Report)
		digests, details = append(digests, sum[:]), append(details, st.enc.EncodeAll(v.Report, nil))
	}
	tag, err := st.pool.Exec(ctx, `INSERT INTO verdicts
			(sample_id, formed_at, outcome, class, scanner_id, fires_at, ruleset, digest, summary, detail)
		SELECT u.sample_id, u.at, coalesce((u.opinion->>'outcome')::outcome, 'ok'), (u.opinion->>'class')::class, $1,
		       (u.opinion->>'fires_at')::smallint, u.ruleset, u.digest, u.opinion - 'outcome' - 'class' - 'fires_at', u.detail
		FROM unnest($2::bigint[], $3::jsonb[], $4::text[], $5::timestamptz[], $6::bytea[], $7::bytea[])
		    AS u (sample_id, opinion, ruleset, at, digest, detail)
		WHERE EXISTS (SELECT 1 FROM samples s WHERE s.id = u.sample_id)
		ORDER BY u.sample_id
		ON CONFLICT (sample_id, scanner_id) DO NOTHING`,
		atomscan, ids, opinions, rulesets, times, digests, details)
	if err != nil {
		return 0, fmt.Errorf("store: fill verdicts: %w", err)
	}
	return tag.RowsAffected(), nil
}
