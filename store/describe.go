package store

import (
	"context"
	"fmt"
	"time"
)

// A file scan sends to the LLM is one whose description triage wants: the
// line that says why. Which files those are is scan's LLM gate's call, and
// the result says what it decided: the artifact's verdict object carries
// llm_admission, "required" (the LLM can change the verdict), "optional"
// (context, skipped when the endpoint is saturated) or "none", which stamp
// keeps on the artifact's scans row. A scan can come back without the
// description the gate admitted it for: the worker had no LLM endpoint, it
// skipped an optional pass under load, or the call failed. (A rescan by such a
// worker leaves a description an earlier scan stored: see writer.fileRows.)
// Such a file is queued as QueueDescribe while its scan is recent, at most
// once a describeWindow, so the queue holds exactly what scan would have sent
// to the LLM and did not get described.
//
// A result that does not say (a worker from before 2026-11-27, or a scan that
// ran no gate) leaves llm_admission NULL, and the rule before it holds for
// that file: it is owed a description when atomscan calls it hostile or
// suspicious.
//
// Only llm's verdict (scanner 4) counts as a description. drift_llm (8) is
// isomer judging a release against the one before it: it says what changed,
// not what the file does, and most flagged files have no earlier release.
//
// A description cannot be asked for alone: postdoc's LLM pass reads what its
// own analysis of the file left in memory, so describing a file is scanning
// it again, and costs that, unless the worker that scanned it left that
// input behind (llm_inputs, see llminput.go).

// describeWindow is how recent a scan must be for its file to be described,
// and how long a file once queued to be described waits before it may be
// again: a worker that cannot describe it does not have it back every minute.
const describeWindow = `interval '7 days'`

// describeGrace is how long after a scan its file waits before it is handed
// out to be described. postdoc posts a verdict first and amends it with the
// LLM's description when that comes back, often minutes later under load;
// the amendment removes the queued row, so a file is scanned again only when
// no description came.
const describeGrace = time.Hour

// owedDescription is true of the file c.sample_id when it is owed a
// description: it has a path, its last scan was made within describeWindow
// and the LLM gate admitted it (or, where the scan did not say, atomscan
// calls it hostile or suspicious), and no LLM has described it. A failed LLM
// call is stored as an llm verdict too (outcome error); it describes nothing,
// so it leaves the file owed — llm_attempts bounds how often it is retried.
const owedDescription = `EXISTS (SELECT 1 FROM scans sc WHERE sc.sample_id = c.sample_id
		AND sc.scanned_at > now() - ` + describeWindow + `
		AND (sc.llm_admission IN ('optional', 'required')
		  OR (sc.llm_admission IS NULL AND EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = c.sample_id
		      AND v.scanner_id = 1 AND v.class IN ('hostile', 'suspicious')))))
	AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = c.sample_id AND v.scanner_id = 4 AND v.outcome = 'ok')
	AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = c.sample_id)`

// describable is the predicate of the scans_describable index: the scans
// whose files owedDescription may hold, the gate's admissions and, where the
// scan did not say, the flagged scans, which hold every file atomscan calls
// hostile or suspicious. SweepDescribe spells it out as it is, so the planner
// matches the index; Upgrade builds the index from it.
const describable = `(llm_admission IN ('optional', 'required') OR (llm_admission IS NULL AND flagged))`

// queueDescribe queues as QueueDescribe the files of c (sample_id) owed a
// description and not queued to be described within describeWindow, handed
// out no sooner than $1 from now, and records the attempt (llm_attempts). A
// file queued higher is left where it is; one queued lower is raised.
// QueueDescribe is $2.
const queueDescribe = `, queued AS (
		INSERT INTO queue (sample_id, priority, retry_at)
		SELECT c.sample_id, $2::smallint, now() + $1::interval FROM c
		WHERE ` + owedDescription + `
		  AND NOT EXISTS (SELECT 1 FROM llm_attempts a WHERE a.sample_id = c.sample_id AND a.at > now() - ` + describeWindow + `)
		ORDER BY c.sample_id
		ON CONFLICT (sample_id) DO UPDATE SET priority = EXCLUDED.priority, retry_at = EXCLUDED.retry_at
		WHERE queue.priority > EXCLUDED.priority
		RETURNING sample_id
	), attempted AS (
		INSERT INTO llm_attempts (sample_id) SELECT sample_id FROM queued ORDER BY sample_id
		ON CONFLICT (sample_id) DO UPDATE SET at = now()
	)`

// describe queues the scanned artifact to be described, after
// describeGrace, when its result leaves it owed a description. A result that
// carries the LLM's opinion, once a successful llm verdict is stored, deletes
// the input the LLM pass read: it has served. A failed call keeps it for the
// retry.
func (w *writer) describe(ctx context.Context) error {
	if w.speaks(0, "llm") {
		tag, err := w.tx.Exec(ctx, `DELETE FROM llm_inputs WHERE sample_id = $1
			AND EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = $1 AND v.scanner_id = $2 AND v.outcome = 'ok')`, w.ids[0], jurors["llm"])
		if err != nil {
			return fmt.Errorf("describe: llm input: %w", err)
		}
		w.stats.LLMInputDropped = tag.RowsAffected() > 0
	}
	if w.outcome[0].outcome != "ok" {
		return nil
	}
	err := w.tx.QueryRow(ctx, `WITH c AS (SELECT $3::bigint AS sample_id)`+queueDescribe+`
		SELECT count(*) FROM queued`, describeGrace, int16(QueueDescribe), w.ids[0]).Scan(&w.stats.Described)
	if err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	return nil
}

// ExpireDescribe drops the rows queued to be described whose file is no
// longer owed a description (described since, no longer admitted, or last
// scanned longer ago than describeWindow), forgets attempts older than that,
// and deletes LLM inputs stored longer ago than that. It returns how many
// rows and inputs it dropped.
func (st *Store) ExpireDescribe(ctx context.Context) (dropped, inputs int64, err error) {
	err = st.pool.QueryRow(ctx, `WITH gone AS (
			DELETE FROM queue q USING (
				SELECT c.sample_id FROM queue c
				WHERE c.priority = $1 AND c.attempts < 8 AND NOT (`+owedDescription+`)
				ORDER BY c.sample_id FOR UPDATE SKIP LOCKED) k
			WHERE q.sample_id = k.sample_id
			RETURNING 1
		), forgotten AS (
			DELETE FROM llm_attempts WHERE at <= now() - `+describeWindow+`
		), expired AS (
			DELETE FROM llm_inputs WHERE stored_at <= now() - `+describeWindow+`
			RETURNING 1
		)
		SELECT (SELECT count(*) FROM gone), (SELECT count(*) FROM expired)`, int16(QueueDescribe)).Scan(&dropped, &inputs)
	if err != nil {
		return 0, 0, fmt.Errorf("store: expire describe: %w", err)
	}
	return dropped, inputs, nil
}

// SweepDescribe queues the files owed a description among the next limit
// describable scans after the cursor, oldest first, made within
// describeWindow and at least describeGrace ago. It returns where to continue, the zero
// Cursor once it has reached the end.
func (st *Store) SweepDescribe(ctx context.Context, after Cursor, limit int) (next Cursor, queued int64, err error) {
	var (
		n    int
		last *time.Time
		id   *int64
	)
	err = st.pool.QueryRow(ctx, `WITH page AS (
			SELECT sample_id, scanned_at FROM scans
			WHERE `+describable+` AND (scanned_at, sample_id) > ($3, $4)
			  AND scanned_at > now() - `+describeWindow+` AND scanned_at <= now() - $6::interval
			ORDER BY scanned_at, sample_id LIMIT $5
		), c AS (SELECT sample_id FROM page)`+queueDescribe+`, tail AS (
			SELECT scanned_at, sample_id FROM page ORDER BY scanned_at DESC, sample_id DESC LIMIT 1
		)
		SELECT (SELECT count(*) FROM page), (SELECT scanned_at FROM tail), (SELECT sample_id FROM tail),
		       (SELECT count(*) FROM queued)`,
		time.Duration(0), int16(QueueDescribe), after.At, after.ID, limit, describeGrace).Scan(&n, &last, &id, &queued)
	if err != nil {
		return Cursor{}, 0, fmt.Errorf("store: sweep describe: %w", err)
	}
	if n < limit || last == nil {
		return Cursor{}, queued, nil
	}
	return Cursor{At: *last, ID: *id}, queued, nil
}
