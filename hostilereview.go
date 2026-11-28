package hopper

// hostilereview.go is the selector behind review-72h and review-30d: the
// population prism renders at /review, "hostile, but not known malware".

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// hostileReviewParkSQL is the permanent park shared by both review queues and
// fallout. All three ask one question of a litmus-hostile sample -- does the
// hostile call stand -- so a completed judgement from any of them settles it
// for the others. Sharing the park is also what lets a row age from review-72h
// into review-30d without being judged twice. Permanent rather than
// queueFilter's cooldown because a rescan does not change the question: a
// sample judged benign is still litmus-hostile the next day, and a cooldown
// would re-offer it on every rescan until it left the 30-day window.
const hostileReviewParkSQL = `
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256
		                     AND r.report_type IN ('review-72h', 'review-30d', 'fallout'))`

// TriageHostileReview returns analyzed top-level litmus-hostile samples (class
// 2) not labeled bad, newest first (created_at), created after createdAfter
// and, when createdBefore is non-zero, at or before it.
//
// This is prism's /review list: litmus class hostile, label anything but bad,
// top-level only. Registry sidecars, skipped rows, empty paths and contained
// members are excluded exactly as TriageFallout excludes them, since both
// mirror the same feed query. Rows carrying a review-72h, review-30d or
// fallout report are skipped permanently; see hostileReviewParkSQL.
//
// A bad ruling drains a row through the label predicate; any other completed
// judgement drains it through the report.
func (db *DB) TriageHostileReview(ctx context.Context, limit int, createdAfter, createdBefore time.Time, f TriageFilter) ([]*Sample, error) {
	if db.pool != nil {
		return db.triageHostileReviewPG(ctx, limit, createdAfter, createdBefore, f)
	}
	return db.triageHostileReviewSQLite(ctx, limit, createdAfter, createdBefore, f)
}

func (db *DB) triageHostileReviewPG(ctx context.Context, limit int, createdAfter, createdBefore time.Time, f TriageFilter) ([]*Sample, error) {
	args := []any{createdAfter}
	ceiling := ""
	if !createdBefore.IsZero() {
		args = append(args, createdBefore)
		ceiling = `
		   AND created_at <= $2`
	}
	extra, fargs := triageFilterClausePG(f, len(args)+1, "samples")
	args = append(args, fargs...)
	args = append(args, limit)
	rows, err := db.pool.Query(ctx,
		`SELECT `+pgSampleCols+` FROM samples
		 WHERE litmus_class = 2 AND label <> 'bad'
		   AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL
		   AND skip = '' AND file_type <> 'registry'`+triageServablePathSQL+`
		   AND created_at > $1`+ceiling+hostileReviewParkSQL+`
		   AND `+uncontainedSQL+extra+`
		 `+triageOrderSQL(f)+` LIMIT $`+strconv.Itoa(len(args)),
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage hostile review: %w", err)
	}
	return scanPGSamples(rows)
}

func (db *DB) triageHostileReviewSQLite(ctx context.Context, limit int, createdAfter, createdBefore time.Time, f TriageFilter) ([]*Sample, error) {
	// Text-formatted because SQLite stores timestamps as RFC3339Nano and a
	// bound time.Time silently matches nothing.
	args := []any{CriticalLevel, SuspiciousCeiling, createdAfter.UTC().Format(time.RFC3339Nano)}
	ceiling := ""
	if !createdBefore.IsZero() {
		args = append(args, createdBefore.UTC().Format(time.RFC3339Nano))
		ceiling = `
		   AND created_at <= ?`
	}
	extra, fargs := triageFilterClauseSQLite(f, "samples")
	args = append(args, fargs...)
	args = append(args, limit)
	//nolint:gosec // G202: predicates and column list are constant; filter values are parameterized via ? args
	rows, err := db.lite.QueryContext(ctx,
		`SELECT `+liteSampleCols+` FROM samples
		 WHERE `+litmusClassSQLite+` = 2 AND label <> 'bad'
		   AND cleave_result IS NOT NULL AND litmus_result IS NOT NULL
		   AND skip = '' AND file_type <> 'registry'`+triageServablePathSQL+`
		   AND created_at > ?`+ceiling+hostileReviewParkSQL+`
		   AND parent = '' AND NOT EXISTS (
		     SELECT 1 FROM sample_locations sl
		      WHERE sl.sha256 = samples.sha256
		        AND sl.parent_sha256 <> '' AND sl.rel IN `+containmentRelsSQL+`)`+extra+`
		 `+triageOrderSQL(f)+` LIMIT ?`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("hopper: triage hostile review: %w", err)
	}
	return scanLiteSamples(rows)
}
