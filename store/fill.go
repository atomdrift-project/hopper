package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// FillReports stores reports, by sample id, for files atomscan judged whose
// stored report says no more than their molecule (a molecule and a risk): all
// an archive's report kept of its members once legacy hopper had cut their
// entries out of it. What the stored report says that the new one does not is
// kept. A file with a fuller report, or no atomscan verdict, is left as it is,
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
