package hopper

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

//go:embed gauntlet_schema.sql
var gauntletSchema string

// GauntletRun is one immutable batch of benchmark observations. An empty
// ObservedAt means the original scan time could not be recovered from history.
// Source identifies the original document, not the machine importing it.
//
// The field order is the JSON key order, which a stored run's digest hashes
// (storeGauntletRun): reordering it would make every stored run conflict
// with its own replay.
//
//nolint:govet // fieldalignment: the order is part of the stored digest
type GauntletRun struct {
	ID          string                   `json:"id"`
	Producer    string                   `json:"producer"`
	ObservedAt  string                   `json:"observed_at"`
	Source      string                   `json:"source"`
	Complete    bool                     `json:"complete"`
	Versions    map[string]string        `json:"versions,omitempty"`
	Rules       map[string]GauntletRules `json:"rules,omitempty"`
	Samples     []GauntletSample         `json:"samples,omitempty"`
	Annotations []json.RawMessage        `json:"annotations,omitempty"`
	Withdrawn   []string                 `json:"withdrawn,omitempty"`
}

// GauntletRules identifies the installed bundles; absent revisions stay unknown.
type GauntletRules struct {
	Channel string `json:"channel,omitempty"`
	Version string `json:"version,omitempty"`
	Traits  string `json:"traits,omitempty"`
	Models  string `json:"models,omitempty"`
}

// GauntletSample preserves a run member independently of the live sample
// catalog. Its field order is part of the run's digest, as GauntletRun's is.
//
//nolint:govet // fieldalignment: the order is part of the stored digest
type GauntletSample struct {
	SHA256   string           `json:"sha256"`
	Label    string           `json:"label"`
	Eligible bool             `json:"eligible"`
	Metadata json.RawMessage  `json:"metadata"`
	Results  []GauntletResult `json:"results,omitempty"`
}

// GauntletResult preserves one scanner outcome and its original verdict fields.
type GauntletResult struct {
	Scanner string          `json:"scanner"`
	Status  string          `json:"status"`
	Payload json.RawMessage `json:"payload"`
}

// GauntletEvidence travels with a selected sample. Completion covers this exact
// key, even if a newer observation arrives while Cyclotron is working.
type GauntletEvidence struct {
	Key        string          `json:"key"`
	RunID      string          `json:"run_id"`
	ObservedAt string          `json:"observed_at"`
	Expected   string          `json:"expected"`
	Status     string          `json:"status"`
	Rules      GauntletRules   `json:"rules"`
	Result     json.RawMessage `json:"result"`
}

var (
	// ErrGauntletConflict reports a run whose identity is already stored
	// with different content; the stored observations stand.
	ErrGauntletConflict = errors.New("gauntlet run identity has different content")
	// ErrGauntletEvidence reports a review of evidence no stored result holds.
	ErrGauntletEvidence = errors.New("unknown gauntlet evidence")
)

// GauntletTime makes lexical timestamp ordering agree with chronological order.
func GauntletTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func gauntletHashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func gauntletHashStrings(parts []string) string {
	// Run ids are this hash of this encoding, so it cannot change. A []string
	// always encodes.
	b, _ := json.Marshal(parts) //nolint:errcheck,errchkjson // a []string always encodes
	return gauntletHashBytes(b)
}

// GauntletRunID is independent of transport retries and git commit times.
// For an undated fragment, source supplies its identity instead of a guessed date.
func GauntletRunID(producer, at, source string) string {
	if at != "" {
		source = ""
	}
	return gauntletHashStrings([]string{producer, at, source})
}

func gauntletEvidenceKey(run GauntletRun, s GauntletSample, r GauntletResult) string {
	rules := run.Rules[r.Scanner]
	version := rules.Version
	if version == "" {
		version = run.Versions[r.Scanner]
	}
	fallback := ""
	if version == "" || rules.Traits == "" || rules.Models == "" {
		fallback = run.ID
	}
	return gauntletHashStrings([]string{
		s.SHA256, r.Scanner, s.Label, r.Status,
		version, rules.Channel, rules.Traits, rules.Models, fallback,
	})
}

func validGauntletSHA(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && strings.ToLower(s) == s
}

// NormalizeGauntletRun validates and canonicalizes a copy, leaving the caller's
// slices untouched. Explicit enum validation keeps unknown outcomes out of triage.
func NormalizeGauntletRun(in GauntletRun) (GauntletRun, error) {
	r := in
	if r.Producer == "" || len(r.Producer) > 200 || r.Source == "" || len(r.Source) > 2000 {
		return r, errors.New("producer and source are required and must be bounded")
	}
	if r.ObservedAt != "" {
		at, err := time.Parse(time.RFC3339Nano, r.ObservedAt)
		if err != nil {
			return r, fmt.Errorf("observed_at: %w", err)
		}
		r.ObservedAt = GauntletTime(at)
	}
	want := GauntletRunID(r.Producer, r.ObservedAt, r.Source)
	if r.ID != "" && r.ID != want {
		return r, errors.New("run id does not match its identity")
	}
	r.ID = want
	r.Samples = slices.Clone(r.Samples)
	slices.SortFunc(r.Samples, func(a, b GauntletSample) int { return strings.Compare(a.SHA256, b.SHA256) })
	for i := range r.Samples {
		s := &r.Samples[i]
		if !validGauntletSHA(s.SHA256) || (i > 0 && r.Samples[i-1].SHA256 == s.SHA256) {
			return r, errors.New("invalid or duplicate sample sha256")
		}
		if s.Label == "withdrawn" {
			r.Withdrawn = append(slices.Clone(r.Withdrawn), s.SHA256)
		}
		switch s.Label {
		case "good", "bad", "withdrawn":
		default:
			return r, fmt.Errorf("invalid cohort label %q", s.Label)
		}
		if err := normalizeGauntletSample(s); err != nil {
			return r, err
		}
	}
	r.Annotations = slices.Clone(r.Annotations)
	for i, b := range r.Annotations {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(b, &object); err != nil || object == nil {
			return r, errors.New("annotation must be an object")
		}
		c, err := json.Marshal(object)
		if err != nil {
			return r, fmt.Errorf("annotation: %w", err)
		}
		r.Annotations[i] = c
	}

	r.Withdrawn = slices.Clone(r.Withdrawn)
	slices.Sort(r.Withdrawn)
	r.Withdrawn = slices.Compact(r.Withdrawn)
	for _, sha := range r.Withdrawn {
		if !validGauntletSHA(sha) {
			return r, errors.New("invalid withdrawal sha256")
		}
	}
	return r, nil
}

// normalizeGauntletSample canonicalizes one sample of a run in place: its
// metadata re-encoded, its results sorted by scanner and checked.
func normalizeGauntletSample(s *GauntletSample) error {
	if len(s.Metadata) == 0 {
		s.Metadata = json.RawMessage(`{}`)
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(s.Metadata, &meta); err != nil || meta == nil {
		return errors.New("sample metadata must be an object")
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("sample metadata: %w", err)
	}
	s.Metadata = b
	s.Results = slices.Clone(s.Results)
	slices.SortFunc(s.Results, func(a, b GauntletResult) int { return strings.Compare(a.Scanner, b.Scanner) })
	for j := range s.Results {
		v := &s.Results[j]
		if v.Scanner == "" || len(v.Scanner) > 100 || (j > 0 && s.Results[j-1].Scanner == v.Scanner) {
			return errors.New("invalid or duplicate scanner")
		}
		switch v.Status {
		case "benign", "detected", "skipped", "error", "nodata":
		default:
			return fmt.Errorf("invalid status %q", v.Status)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(v.Payload, &payload); err != nil || payload == nil {
			return errors.New("verdict payload must be an object")
		}
		for key, want := range map[string]string{"scanner": v.Scanner, "status": v.Status} {
			var got string
			if json.Unmarshal(payload[key], &got) != nil || got != want {
				return fmt.Errorf("verdict payload %s disagrees with result", key)
			}
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("verdict payload: %w", err)
		}
		v.Payload = b
	}
	return nil
}

type gauntletRow interface{ Scan(...any) error }

// StoreGauntletRun commits a whole batch or none of it. An identical retry is a
// no-op; a conflicting retry never overwrites the original observations.
func (db *DB) StoreGauntletRun(ctx context.Context, in GauntletRun) (bool, error) {
	r, err := NormalizeGauntletRun(in)
	if err != nil {
		return false, err
	}
	if db.pool != nil {
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return false, err
		}
		defer tx.Rollback(ctx) //nolint:errcheck // commit or rollback below owns the transaction
		fresh, err := storeGauntletRun(r,
			func(q string, a ...any) error { _, err := tx.Exec(ctx, q, a...); return err },
			func(q string, a ...any) gauntletRow { return tx.QueryRow(ctx, q, a...) })
		if err != nil {
			return false, err
		}
		return fresh, tx.Commit(ctx)
	}
	tx, err := db.lite.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // commit or rollback owns the transaction
	fresh, err := storeGauntletRun(r,
		func(q string, a ...any) error { _, err := tx.ExecContext(ctx, q, a...); return err },
		func(q string, a ...any) gauntletRow { return tx.QueryRowContext(ctx, q, a...) })
	if err != nil {
		return false, err
	}
	return fresh, tx.Commit()
}

func storeGauntletRun(r GauntletRun, exec func(string, ...any) error, row func(string, ...any) gauntletRow) (bool, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	digest := gauntletHashBytes(payload)
	meta := r
	meta.Samples = nil
	b, err := json.Marshal(meta)
	if err != nil {
		return false, err
	}
	// A unique insert serializes competing submissions before the digest check.
	var inserted string
	err = row(`INSERT INTO gauntlet_runs(id,producer,observed_at,source,digest,metadata)
 VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING RETURNING id`, r.ID, r.Producer, r.ObservedAt, r.Source, digest, string(b)).Scan(&inserted)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if inserted == "" {
		var stored string
		if err := row(`SELECT digest FROM gauntlet_runs WHERE id=$1`, r.ID).Scan(&stored); err != nil {
			return false, err
		}
		if stored != digest {
			return false, ErrGauntletConflict
		}
		return false, nil
	}
	for _, s := range r.Samples {
		err := exec(`INSERT INTO gauntlet_samples(run_id,sha256,label,eligible,metadata) VALUES($1,$2,$3,$4,$5)`,
			r.ID, s.SHA256, s.Label, s.Eligible, string(s.Metadata))
		if err != nil {
			return false, err
		}
		for _, v := range s.Results {
			err := exec(`INSERT INTO gauntlet_results(run_id,sha256,scanner,status,evidence_key,payload) VALUES($1,$2,$3,$4,$5,$6)`,
				r.ID, s.SHA256, v.Scanner, v.Status, gauntletEvidenceKey(r, s, v), string(v.Payload))
			if err != nil {
				return false, err
			}
		}
	}
	for _, sha := range r.Withdrawn {
		if err := exec(`INSERT INTO gauntlet_withdrawals(run_id,sha256) VALUES($1,$2) ON CONFLICT DO NOTHING`, r.ID, sha); err != nil {
			return false, err
		}
	}
	return true, nil
}

// History statements deliberately use the common SQL subset. Only transaction
// and row plumbing differ between Postgres and SQLite.
func (db *DB) queryGauntlet(ctx context.Context, q string, args []any, visit func(sqlRows) error) error {
	if db.pool != nil {
		rows, err := db.pool.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		if err := visit(rows); err != nil {
			return err
		}
		return rows.Err()
	}
	rows, err := db.lite.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck // read-only rows
	if err := visit(rows); err != nil {
		return err
	}
	return rows.Err()
}

// GauntletRun returns the stored run with id, its samples and their results;
// sql.ErrNoRows when there is none.
func (db *DB) GauntletRun(ctx context.Context, id string) (*GauntletRun, error) {
	var r GauntletRun
	found := false
	err := db.queryGauntlet(ctx, `SELECT metadata FROM gauntlet_runs WHERE id=$1`, []any{id}, func(rows sqlRows) error {
		if !rows.Next() {
			return nil
		}
		found = true
		var b string
		if err := rows.Scan(&b); err != nil {
			return err
		}
		return json.Unmarshal([]byte(b), &r)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, sql.ErrNoRows
	}
	bySHA := map[string]int{}
	err = db.queryGauntlet(ctx, `SELECT sha256,label,eligible,metadata FROM gauntlet_samples WHERE run_id=$1 ORDER BY sha256`,
		[]any{id}, func(rows sqlRows) error {
			for rows.Next() {
				var s GauntletSample
				var b string
				if err := rows.Scan(&s.SHA256, &s.Label, &s.Eligible, &b); err != nil {
					return err
				}
				s.Metadata = json.RawMessage(b)
				bySHA[s.SHA256] = len(r.Samples)
				r.Samples = append(r.Samples, s)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	err = db.queryGauntlet(ctx, `SELECT sha256,scanner,status,payload FROM gauntlet_results WHERE run_id=$1 ORDER BY sha256,scanner`,
		[]any{id}, func(rows sqlRows) error {
			for rows.Next() {
				var sha, b string
				var v GauntletResult
				if err := rows.Scan(&sha, &v.Scanner, &v.Status, &b); err != nil {
					return err
				}
				v.Payload = json.RawMessage(b)
				i := bySHA[sha]
				r.Samples[i].Results = append(r.Samples[i].Results, v)
			}
			return nil
		})
	return &r, err
}

// Select the latest usable observation BEFORE checking for a failure. Otherwise
// an old miss resurfaces even after a newer scan has demonstrated a fix.
const gauntletCandidatesSQL = `WITH ranked AS (
 SELECT g.run_id,g.sha256,g.label,v.status,v.evidence_key,v.payload,r.observed_at,r.metadata,
 row_number() OVER (PARTITION BY g.sha256 ORDER BY r.observed_at DESC,g.run_id DESC) AS rank
 FROM gauntlet_results v JOIN gauntlet_samples g ON g.run_id=v.run_id AND g.sha256=v.sha256
 JOIN gauntlet_runs r ON r.id=g.run_id
 WHERE v.scanner='ascan' AND v.status IN ('benign','detected') AND g.eligible AND r.observed_at<>''
) SELECT c.sha256,c.run_id,c.label,c.status,c.evidence_key,c.payload,c.observed_at,c.metadata
 FROM ranked c JOIN samples s ON s.sha256=c.sha256
 WHERE c.rank=1 AND s.parent='' AND s.skip=''
 AND (c.label<>'good' OR NOT EXISTS(SELECT 1 FROM gauntlet_withdrawals w WHERE w.sha256=c.sha256))
 AND s.label NOT IN ('dual-use','inconclusive')
 AND ((c.label='good' AND c.status='detected') OR (c.label='bad' AND c.status='benign'))
 AND NOT EXISTS(SELECT 1 FROM reports p WHERE p.sha256=c.sha256 AND p.report_type='gauntlet' AND p.evidence_key=c.evidence_key)`

// TriageGauntlet returns up to n files a published gauntlet run saw atomscan
// misjudge, oldest observation first, leaving out excluded digests; each
// carries the observation it answers in Sample.Gauntlet.
func (db *DB) TriageGauntlet(ctx context.Context, n int, excluded []string) ([]*Sample, error) {
	args := []any{}
	var b strings.Builder
	b.WriteString(gauntletCandidatesSQL)
	for _, sha := range excluded {
		args = append(args, sha)
		fmt.Fprintf(&b, " AND c.sha256<>$%d", len(args))
	}
	args = append(args, n)
	fmt.Fprintf(&b, " ORDER BY c.observed_at,c.sha256 LIMIT $%d", len(args))
	q := b.String()
	type candidate struct {
		sha string
		e   GauntletEvidence
	}
	var picks []candidate
	err := db.queryGauntlet(ctx, q, args, func(rows sqlRows) error {
		for rows.Next() {
			var c candidate
			var payload, metadata string
			if err := rows.Scan(&c.sha, &c.e.RunID, &c.e.Expected, &c.e.Status, &c.e.Key, &payload, &c.e.ObservedAt, &metadata); err != nil {
				return err
			}
			var run GauntletRun
			if err := json.Unmarshal([]byte(metadata), &run); err != nil {
				return err
			}
			c.e.Rules = run.Rules["ascan"]
			c.e.Result = json.RawMessage(payload)
			picks = append(picks, c)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(picks) == 0 {
		return []*Sample{}, nil
	}
	// Fetch one bounded light projection, never the large analysis blobs.
	shas := make([]string, len(picks))
	evidence := map[string]*GauntletEvidence{}
	for i := range picks {
		shas[i] = picks[i].sha
		evidence[picks[i].sha] = &picks[i].e
	}
	samples, err := db.lightSamples(ctx, shas)
	if err != nil {
		return nil, err
	}
	bySHA := map[string]*Sample{}
	for _, s := range samples {
		s.Gauntlet = evidence[s.SHA256]
		bySHA[s.SHA256] = s
	}
	out := make([]*Sample, 0, len(samples))
	for i := range picks {
		if s := bySHA[picks[i].sha]; s != nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// lightSamples returns the light projection of the samples with these
// digests, which are passed as one argument: an array to Postgres, a JSON
// array to SQLite.
func (db *DB) lightSamples(ctx context.Context, shas []string) ([]*Sample, error) {
	if db.pool != nil {
		rows, err := db.pool.Query(ctx, `SELECT `+pgSampleColsLight+` FROM samples WHERE sha256 = ANY($1)`, shas)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanPGSamplesLight(rows)
	}
	list, err := json.Marshal(shas)
	if err != nil {
		return nil, err
	}
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleColsLight+` FROM samples WHERE sha256 IN (SELECT value FROM json_each(?))`, string(list))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only rows
	return scanLiteSamplesLight(rows)
}

// CompleteGauntlet records a review only for evidence that actually belongs to
// this sample. A unique key makes an acknowledgment safe to retry after a timeout.
func (db *DB) CompleteGauntlet(ctx context.Context, r *Report) error {
	if r.EvidenceKey == "" {
		return errors.New("gauntlet completion requires an evidence key")
	}
	var exists bool
	err := db.queryGauntlet(ctx, `SELECT 1 FROM gauntlet_results WHERE sha256=$1 AND scanner='ascan' AND evidence_key=$2 LIMIT 1`,
		[]any{r.SHA256, r.EvidenceKey}, func(rows sqlRows) error { exists = rows.Next(); return nil })
	if err != nil {
		return err
	}
	if !exists {
		return ErrGauntletEvidence
	}
	q := `INSERT INTO reports(sha256,report_type,provider,content,evidence_key) VALUES($1,'gauntlet',$2,$3,$4) ON CONFLICT DO NOTHING`
	args := []any{r.SHA256, r.Provider, r.Content, r.EvidenceKey}
	if db.pool != nil {
		_, err = db.pool.Exec(ctx, q, args...)
	} else {
		_, err = db.lite.ExecContext(ctx, q, args...)
	}
	return err
}

// TransferGauntlet copies history through the same transactional ingestion path.
// Separate withdrawal facts make transfer order irrelevant.
func TransferGauntlet(ctx context.Context, dst, src *DB) error {
	var ids []string
	err := src.queryGauntlet(ctx, `SELECT id FROM gauntlet_runs ORDER BY observed_at,id`, nil, func(rows sqlRows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := src.GauntletRun(ctx, id)
		if err != nil {
			return err
		}
		if _, err := dst.StoreGauntletRun(ctx, *r); err != nil {
			return err
		}
	}
	return nil
}

// GauntletDepth counts the same eligible evidence as selection, without fetching
// live analysis blobs or constructing a Sample for each row just to count it.
func (db *DB) GauntletDepth(ctx context.Context) (counts map[string]int64, capped bool, err error) {
	counts = map[string]int64{"false_positive": 0, "miss": 0}
	q := `SELECT label,count(*) FROM (` + gauntletCandidatesSQL + ` ORDER BY c.observed_at,c.sha256 LIMIT $1) pending GROUP BY label`
	err = db.queryGauntlet(ctx, q, []any{TriageDepthCap}, func(rows sqlRows) error {
		for rows.Next() {
			var label string
			var count int64
			if err := rows.Scan(&label, &count); err != nil {
				return err
			}
			if label == "good" {
				counts["false_positive"] = count
			} else {
				counts["miss"] = count
			}
		}
		return nil
	})
	return counts, counts["false_positive"]+counts["miss"] >= TriageDepthCap, err
}
