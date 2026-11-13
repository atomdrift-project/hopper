package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// The triage queues: named selections cyclotron's workers pull from, each the
// newest (or most telling) files whose stored label and analysis disagree in
// one particular way. Working a file resolves the disagreement or files a
// report, so a queue drains itself. They are hopper's legacy queues
// (triagequeues.go) on the verdict schema; PLAN.md, "Triage queues on the new
// tables", maps each legacy column and says where a queue was narrowed.
//
// A queue with a time window starts from the flagged scans in it
// (scans_flagged): about 2% of scans, so a window of a day is tens of
// thousands of rows, where all the scans in it are a million.

// TriageDepthCap bounds a depth count: a queue at the cap reports the cap.
const TriageDepthCap = 10_000

// trustedSources are the feeds whose citation of a good file asks for a
// second opinion on its own. hopper.TrustedBadSources is the same list for
// the legacy queues; it goes with them.
var trustedSources = []string{"bazaar", "virussign", "malshare", "vxug", "osm", "osv", "ghsa", "extsentry", "vsxsentry"}

// Tuning carried over from the legacy registry. The windows hold each queue
// near a thousand files in production (PLAN.md has the counts).
const (
	perRouteK         = 10   // highest and lowest: files per file type in one selection
	fpTraitWindow     = 5000 // fp-trait: newest files the worst trait is counted over
	driftCandidates   = 5000 // version-drift: newest candidates given a sibling probe
	pinnedPerPackage  = 3    // sighted-pinned: files of one package per round
	sightedOverfetch  = 256  // sighted: claims read past the page, for matches that fail later tests
	day               = 24 * time.Hour
	hostileWindow     = 12 * time.Hour
	suspiciousWindow  = 12 * time.Hour
	badWindow         = day
	discordWindow     = day
	fpTraitWindowTime = day
	popularWindow     = day
	popularTailWindow = 21 * day
	highestWindow     = 3 * day
	lowestWindow      = 30 * day
	createdWindow     = 7 * day // version-drift and fallout: files created this recently
)

// Candidate is one file a triage queue hands out: what a worker needs to
// fetch it and to say what was decided about it.
type Candidate struct {
	CreatedAt time.Time
	// ScannedAt is the file's last scan; zero if it was never scanned.
	ScannedAt time.Time
	// Gauntlet is the observation that put the file in the gauntlet queue.
	Gauntlet    *GauntletPick
	Path        string // where it was most recently seen on disk
	Feed        string // the feed of that path
	Label       string
	LabelSource string
	Name        string // the release's PURL without a version
	Version     string
	FileType    string
	SHA256      []byte
	// Top is atomscan's strongest findings.
	Top       []Finding
	SizeBytes int64
	ID        int64
}

// GauntletPick is the newest usable gauntlet observation of a file, as the
// gauntlet queue picked it. Metadata is the run's, as published.
type GauntletPick struct {
	RunID      string
	Expected   string // the label the run expected
	Status     string // what atomscan said in the run
	Key        string // evidence key a review answers, once
	ObservedAt string
	Metadata   json.RawMessage
	Payload    json.RawMessage
}

// TriageQueueNames returns every queue name, sorted.
func TriageQueueNames() []string {
	names := make([]string, 0, len(triageQueues)+1)
	names = append(names, "gauntlet") // Store.gauntlet, which carries its observations
	for name := range triageQueues {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Triage returns up to n files from the named queue, in its order, leaving
// out the files whose digests are in excluded.
func (st *Store) Triage(ctx context.Context, queue string, n int, excluded [][]byte) ([]Candidate, error) {
	if excluded == nil {
		excluded = [][]byte{} // a NULL array would exclude everything
	}
	if queue == "gauntlet" {
		return st.gauntlet(ctx, n, excluded)
	}
	selectIDs, ok := triageQueues[queue]
	if !ok {
		return nil, fmt.Errorf("store: triage: no queue %q", queue)
	}
	ids, err := selectIDs(ctx, st, queue, n, excluded, perRouteK)
	if err != nil {
		return nil, fmt.Errorf("store: triage %s: %w", queue, err)
	}
	return st.candidates(ctx, ids, nil)
}

// TriageDepth reports how many files the named queue would hand out, up to
// TriageDepthCap. A depth is the queue's own selection counted, so it cannot
// drift from what the queue hands out; highest and lowest lift their
// per-type bound so the count is the population rather than one batch.
func (st *Store) TriageDepth(ctx context.Context, queue string) (depth int64, capped bool, err error) {
	var n int
	if queue == "gauntlet" {
		picks, err := st.gauntlet(ctx, TriageDepthCap, [][]byte{})
		if err != nil {
			return 0, false, err
		}
		n = len(picks)
	} else {
		selectIDs, ok := triageQueues[queue]
		if !ok {
			return 0, false, fmt.Errorf("store: triage depth: no queue %q", queue)
		}
		ids, err := selectIDs(ctx, st, queue, TriageDepthCap, [][]byte{}, TriageDepthCap)
		if err != nil {
			return 0, false, fmt.Errorf("store: triage depth %s: %w", queue, err)
		}
		n = len(ids)
	}
	return int64(n), n >= TriageDepthCap, nil
}

// triageQueue selects a queue's files: up to n sample ids in its order, k
// files per file type for the queues that bound one.
type triageQueue func(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, k int) ([]int64, error)

// num reads a JSON number from a verdict summary, 0 when it is absent or not
// a number, so a malformed summary narrows a queue instead of failing it.
func num(expr string) string {
	return "coalesce(CASE WHEN jsonb_typeof(" + expr + ") = 'number' THEN (" + expr + ")::numeric END, 0)"
}

var (
	floorHostile    = num("f.summary->'hostile'")    // crit 5 findings: legacy max_crit >= 5
	floorSuspicious = num("f.summary->'suspicious'") // crit 4 findings
)

// SQL every sample queue shares, over s (samples), sc (scans) and a
// (atomscan's verdict). $1 is the queue's name, $2 the excluded digests, $3
// the page size.
const (
	// triageShared: the labels triage works, the caller's exclusions, and the
	// cooldown a report imposes: a file is parked while its report is newer
	// than its last scan or younger than 72 hours.
	triageShared = `s.label IN ('bad', 'good', 'unknown', 'sighted')
		AND s.sha256 <> ALL ($2::bytea[])
		AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id AND r.report_type = $1
		                AND (r.created_at > sc.scanned_at OR r.created_at > now() - interval '72 hours'))`
	// triageServable: judged, and on disk to be fetched.
	triageServable = `a.outcome = 'ok' AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)`
	// triageSettled: not held by a marker or a good/bad conflict (legacy skip = '').
	triageSettled = `s.label_source IS DISTINCT FROM 'conflict' AND s.label_source IS DISTINCT FROM 'marker'`

	// triageRecent: the flagged scans in the window ($4), with the verdicts
	// the queues read beside them.
	triageRecent = ` FROM scans sc
		JOIN samples s ON s.id = sc.sample_id
		JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = 1
		LEFT JOIN verdicts f ON f.sample_id = s.id AND f.scanner_id = 2
		LEFT JOIN verdicts m ON m.sample_id = s.id AND m.scanner_id = 3
		WHERE sc.flagged AND sc.scanned_at > now() - $4::interval`
	// triageAll: every file, for the queues without a window.
	triageAll = ` FROM samples s
		LEFT JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = 1
		LEFT JOIN scans sc ON sc.sample_id = s.id
		LEFT JOIN verdicts f ON f.sample_id = s.id AND f.scanner_id = 2
		WHERE true`

	newest = ` ORDER BY s.created_at DESC, s.id DESC`
	// repair: files no sighting names first; nobody else will catch them.
	repair = ` ORDER BY named(s.sha256, s.name_id, s.version), s.created_at DESC, s.id DESC`
	stale  = ` ORDER BY sc.scanned_at, s.id`
)

// windowed is a queue that is its flagged scans in a window, a predicate and
// an order.
func windowed(window time.Duration, where, order string) triageQueue {
	return func(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
		return st.sampleIDs(ctx, `SELECT s.id`+triageRecent+` AND `+triageShared+` AND `+triageServable+` AND `+where+order+` LIMIT $3`,
			queue, excluded, n, window)
	}
}

// sampleIDs runs a queue's selection.
func (st *Store) sampleIDs(ctx context.Context, query string, args ...any) ([]int64, error) {
	rows, err := st.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

var (
	unconvictedHostile    = `s.label IN ('good', 'unknown') AND ` + triageSettled + ` AND ` + floorHostile + ` >= 1`
	unconvictedSuspicious = `s.label IN ('good', 'unknown') AND ` + triageSettled + ` AND ` + floorHostile + ` = 0 AND ` +
		floorSuspicious + ` >= 2`
	popularPackage = `EXISTS (SELECT 1 FROM names n JOIN popular_packages p ON p.purl_base = n.name WHERE n.id = s.name_id)`
	popularOrder   = ` ORDER BY (SELECT p.rank FROM names n JOIN popular_packages p ON p.purl_base = n.name WHERE n.id = s.name_id),
		` + floorHostile + ` DESC, ` + floorSuspicious + ` DESC, s.id DESC`
	popular = `s.label_source IS DISTINCT FROM 'conflict' AND ` + floorHostile + ` >= 1 AND ` + popularPackage
)

// triageQueues holds every queue but gauntlet: files a published gauntlet run
// saw atomscan misjudge, read by Store.gauntlet, which carries the
// observation with each file.
var triageQueues = map[string]triageQueue{
	// bad: labelled bad, and the floor does not convict: a miss to write
	// traits for.
	"bad": windowed(badWindow, `s.label = 'bad' AND `+triageSettled+` AND `+floorHostile+` = 0 AND `+floorSuspicious+` <= 1`, newest),

	// unconvicted: good or unknown files the floor convicts, cut by what a
	// mistake costs. Their -stale twins take the oldest scan first.
	"unconvicted-hostile":          windowed(hostileWindow, unconvictedHostile, repair),
	"unconvicted-suspicious":       windowed(suspiciousWindow, unconvictedSuspicious, repair),
	"unconvicted-hostile-stale":    windowed(hostileWindow, unconvictedHostile, stale),
	"unconvicted-suspicious-stale": windowed(suspiciousWindow, unconvictedSuspicious, stale),

	// discord: the floor and the model disagree about the same bytes.
	"discord": windowed(discordWindow, triageSettled+` AND m.class IS NOT NULL
		AND ((`+floorHostile+` >= 1 AND m.class = 'benign')
		  OR (`+floorHostile+` = 0 AND `+floorSuspicious+` = 0 AND m.class = 'hostile'))`, newest),

	// popular: a popular package the floor convicts; the tail is the same
	// files scanned one to 21 days ago. Ordered by the package's rank, then
	// by the strength of the floor's evidence (cleave's risk score, which
	// legacy ordered by, is not stored).
	"popular": windowed(popularWindow, popular, popularOrder),
	"popular-tail": windowed(popularTailWindow, popular+` AND sc.scanned_at <= now() - interval '24 hours'`,
		popularOrder),

	// fallout: the model calls it hostile and either no LLM explained it or
	// nobody outside cited it. Files created in the last week, outside any
	// archive; one report retires a file for good.
	"fallout": windowed(createdWindow, triageSettled+` AND m.class = 'hostile' AND coalesce(s.file_type, '') <> 'registry'
		AND s.created_at > now() - $4::interval
		AND (NOT named(s.sha256, s.name_id, s.version) OR NOT EXISTS (SELECT 1 FROM verdicts lv WHERE lv.sample_id = s.id AND lv.scanner_id = 4
		                               AND coalesce(lv.summary->>'reason', '') <> ''))
		AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id AND r.report_type = 'fallout')
		AND NOT EXISTS (SELECT 1 FROM contents c WHERE c.child_ids @> ARRAY[s.id])`, newest),

	"fp-trait":      fpTrait,
	"version-drift": versionDrift,
	// highest: good or unknown files the model fires on most tightly, per
	// file type. The archive's own ml row has its members folded in, so a
	// member that fires brings its archive here, as legacy collapsed members
	// onto it.
	"highest": outlier(`s.label IN ('good', 'unknown')`, `m.fires_at`, highestWindow),
	// lowest: bad files the model is least sure of, per file type. Top-level
	// files only: legacy also took bad members, which rule 8 mostly no longer
	// creates.
	"lowest": outlier(`s.label = 'bad'`,
		`CASE WHEN jsonb_typeof(m.summary->'prob') = 'number' THEN (m.summary->'prob')::numeric END`, lowestWindow),
	"acquit":         acquit,
	"second":         second,
	"review":         review,
	"sighted":        sighted,
	"sighted-pinned": sightedPinned,
}

// fpTrait: every file in the batch fires the same trait, the one on the most
// good files among the newest scanned in the last day, so one bad rule is
// one edit rather than N separate fixes.
func fpTrait(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	return st.sampleIDs(ctx, `WITH win AS MATERIALIZED (
			SELECT s.id, s.created_at, a.summary->'top' AS top`+triageRecent+`
			  AND `+triageShared+` AND `+triageServable+` AND s.label = 'good' AND `+triageSettled+`
			  AND `+floorHostile+` + `+floorSuspicious+` >= 1
			  AND coalesce(CASE WHEN jsonb_typeof(a.summary->'top') = 'array' THEN jsonb_array_length(a.summary->'top') END, 0) > 0
			ORDER BY s.created_at DESC, s.id DESC LIMIT $5
		), worst AS (
			SELECT e->>'id' AS trait FROM win, jsonb_array_elements(win.top) e
			WHERE `+num("e->'crit'")+` >= 4
			GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 1
		)
		SELECT win.id FROM win, worst
		WHERE win.top @> jsonb_build_array(jsonb_build_object('id', worst.trait))
		ORDER BY win.created_at DESC, win.id DESC LIMIT $3`,
		queue, excluded, n, fpTraitWindowTime, fpTraitWindow)
}

// versionDrift: this release fires, an earlier release of the same package
// did not and is labelled good. Compromise or an over-firing rule; the clean
// sibling gives the judge a diff. Files created in the last week: a scan
// follows creation, so they are among the week's flagged scans.
func versionDrift(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	return st.sampleIDs(ctx, `WITH cand AS MATERIALIZED (
			SELECT s.id, s.name_id, s.created_at`+triageRecent+`
			  AND `+triageShared+` AND `+triageServable+` AND s.label IN ('good', 'unknown') AND `+triageSettled+`
			  AND `+floorHostile+` + `+floorSuspicious+` >= 1 AND s.name_id IS NOT NULL
			  AND s.created_at > now() - $4::interval
			ORDER BY s.created_at DESC, s.id DESC LIMIT $5
		)
		SELECT cand.id FROM cand
		WHERE EXISTS (
			SELECT 1 FROM samples p JOIN verdicts pa ON pa.sample_id = p.id AND pa.scanner_id = 1 AND pa.outcome = 'ok'
			WHERE p.name_id = cand.name_id AND p.id <> cand.id AND p.label = 'good'
			  AND p.label_source IS DISTINCT FROM 'conflict' AND p.label_source IS DISTINCT FROM 'marker'
			  AND NOT EXISTS (SELECT 1 FROM verdicts pf WHERE pf.sample_id = p.id AND pf.scanner_id = 2 AND pf.class <> 'benign')
			  AND p.created_at <= cand.created_at AND (p.created_at < cand.created_at OR p.id < cand.id))
		ORDER BY cand.created_at DESC, cand.id DESC LIMIT $3`,
		queue, excluded, n, createdWindow, driftCandidates)
}

// outlier is the shape highest and lowest share: per file type, the k files
// whose model reading (score: a numeric SQL expression, NULL for none) is
// most extreme, best first, then round by round across types. A report
// retires a file for good; a "missing" report (the bytes could not be
// served) parks it for 96 hours. Files created in the last 48 hours are left
// for the other queues to settle first.
func outlier(where, score string, window time.Duration) triageQueue {
	return func(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, k int) ([]int64, error) {
		return st.sampleIDs(ctx, `WITH c AS (
			SELECT s.id, coalesce(s.file_type, '') AS route,
			       `+score+` AS score`+triageRecent+`
			  AND `+triageShared+` AND `+triageServable+` AND `+triageSettled+` AND `+where+`
			  AND s.created_at < now() - interval '48 hours'
			  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id
			                  AND (r.report_type = $1 OR (r.report_type = 'missing' AND r.created_at > now() - interval '96 hours')))
		), r AS (
			SELECT id, score, row_number() OVER (PARTITION BY route ORDER BY score, id DESC) AS rank
			FROM c WHERE score IS NOT NULL AND score >= 0
		)
		SELECT id FROM r WHERE rank <= $5 ORDER BY rank, score, id DESC LIMIT $3`,
			queue, excluded, n, window, k)
	}
}

// acquit: labelled bad, the floor convicts, but the file was fetched rather
// than reported (no feed in its provenance) and nobody outside names it:
// detection is the only evidence, so it may be wrong. Three days old at
// least; one report retires it.
func acquit(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	return st.sampleIDs(ctx, `SELECT s.id`+triageAll+`
		  AND s.label = 'bad' AND jsonb_typeof(s.provenance) = 'object' AND NOT s.provenance ? 'feed'
		  AND `+triageShared+` AND `+triageServable+` AND s.label_source IS DISTINCT FROM 'conflict'
		  AND `+floorHostile+` >= 1 AND `+floorHostile+` + `+floorSuspicious+` >= 2
		  AND s.created_at < now() - interval '72 hours'
		  AND NOT named(s.sha256, s.name_id, s.version)
		  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id AND r.report_type = 'acquit')`+newest+` LIMIT $3`,
		queue, excluded, n)
}

// second: good files that a trusted feed, or two independent operators, say
// are malicious, and the floor does not convict: a second opinion. Settled a
// day after their scan; a report holds until a trusted feed cites the file
// again. It starts from the files marked cited (samples_cited_good) and asks
// the ledger itself who cites them, so a mark a withdrawn claim left behind
// costs a row and changes nothing.
func second(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	const cites = `(SELECT g.source, g.operator, g.first_seen FROM sightings g WHERE g.subject = encode(s.sha256, 'hex')
		UNION ALL SELECT g.source, g.operator, g.first_seen FROM names n JOIN sightings g ON g.subject = n.name
		WHERE n.id = s.name_id AND covers(g.affected, s.version))`
	return st.sampleIDs(ctx, `SELECT s.id`+triageAll+`
		  AND s.label = 'good' AND s.cited AND `+triageShared+` AND `+triageServable+`
		  AND NOT (`+floorHostile+` >= 1 OR `+floorHostile+` + `+floorSuspicious+` >= 2)
		  AND sc.scanned_at < now() - interval '24 hours'
		  AND (EXISTS (SELECT 1 FROM `+cites+` c WHERE c.source = ANY ($4))
		    OR (SELECT count(DISTINCT c.operator) FROM `+cites+` c) >= 2)
		  AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id AND r.report_type = 'second'
		                  AND r.created_at > coalesce((SELECT max(c.first_seen) FROM `+cites+` c WHERE c.source = ANY ($4)), '-infinity'))`+
		newest+` LIMIT $3`,
		queue, excluded, n, trustedSources)
}

// review: unknown files someone put under review/.
func review(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	return st.sampleIDs(ctx, `SELECT s.id
		FROM (SELECT DISTINCT sample_id FROM locations WHERE path LIKE 'review/%') l
		JOIN samples s ON s.id = l.sample_id
		JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = 1
		LEFT JOIN scans sc ON sc.sample_id = s.id
		WHERE s.label = 'unknown' AND a.outcome = 'ok' AND `+triageSettled+` AND `+triageShared+newest+` LIMIT $3`,
		queue, excluded, n)
}

// sightedCandidate is what a file a claim names must be for the sighted
// queues: not bad, judged, on disk, settled, and never reported on by
// sighted (a report there is final for both queues).
var sightedCandidate = `s.label IN ('good', 'unknown', 'sighted') AND ` + triageServable + ` AND ` + triageSettled + `
	AND ` + triageShared + `
	AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.sample_id = s.id AND r.report_type = 'sighted')`

// sighted: every file a malicious or suspicious claim names, newest claim
// first, to verify the claim (covers() decides which releases a claim
// names). Files sighted-pinned serves are left to it.
func sighted(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	const files = ` JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = 1 LEFT JOIN scans sc ON sc.sample_id = s.id`
	return st.sampleIDs(ctx, `WITH digests AS (
			SELECT x.id, g.first_seen FROM sightings g
			CROSS JOIN LATERAL (SELECT s.id FROM samples s`+files+`
				WHERE s.sha256 = decode(g.subject, 'hex') AND `+sightedCandidate+`) x
			WHERE g.claim IN ('malicious', 'suspicious') AND NOT starts_with(g.subject, 'pkg:') AND g.subject ~ '^[0-9a-f]{64}$'
			ORDER BY g.first_seen DESC LIMIT $3::int + $4::int
		), packages AS (
			SELECT x.id, g.first_seen FROM sightings g
			CROSS JOIN LATERAL (SELECT s.id FROM names n JOIN samples s ON s.name_id = n.id`+files+`
				WHERE n.name = g.subject AND covers(g.affected, s.version) AND `+sightedCandidate+`
				LIMIT $3::int + $4::int) x
			WHERE g.claim IN ('malicious', 'suspicious') AND starts_with(g.subject, 'pkg:')
			ORDER BY g.first_seen DESC LIMIT $3::int + $4::int
		), latest AS (
			SELECT DISTINCT ON (id) id, first_seen FROM (SELECT id, first_seen FROM digests UNION ALL SELECT id, first_seen FROM packages) u
			ORDER BY id, first_seen DESC
		)
		SELECT l.id FROM latest l JOIN samples s ON s.id = l.id
		WHERE NOT EXISTS (SELECT 1 FROM names n JOIN sightings sp ON sp.subject = n.name
		                  WHERE n.id = s.name_id AND sp.claim IN ('malicious', 'suspicious')
		                    AND s.version = ANY (exact_versions(sp.affected)) AND sp.first_seen > now() - interval '24 hours')
		ORDER BY l.first_seen DESC, s.created_at DESC, s.id DESC LIMIT $3`,
		queue, excluded, n, sightedOverfetch)
}

// sightedPinned: releases a claim of the last day names by exact version
// (exact_versions()),
// a few of each package per round so one package's long list does not crowd
// out the rest.
func sightedPinned(ctx context.Context, st *Store, queue string, n int, excluded [][]byte, _ int) ([]int64, error) {
	return st.sampleIDs(ctx, `WITH m AS (
			SELECT s.id, min(g.first_seen) AS sighted FROM sightings g
			JOIN names n ON n.name = g.subject
			JOIN samples s ON s.name_id = n.id AND s.version = ANY (exact_versions(g.affected))
			WHERE g.claim IN ('malicious', 'suspicious') AND starts_with(g.subject, 'pkg:')
			  AND g.first_seen > now() - interval '24 hours'
			GROUP BY s.id
		), c AS (
			SELECT m.id, m.sighted, s.name_id, s.created_at FROM m
			JOIN samples s ON s.id = m.id
			JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = 1
			LEFT JOIN scans sc ON sc.sample_id = s.id
			WHERE `+sightedCandidate+`
		), r AS (
			SELECT id, name_id, row_number() OVER (PARTITION BY name_id ORDER BY sighted, created_at, id) AS rank,
			       min(sighted) OVER (PARTITION BY name_id) AS first
			FROM c
		)
		SELECT id FROM r ORDER BY (rank - 1) / $4, first, name_id, rank LIMIT $3`,
		queue, excluded, n, pinnedPerPackage)
}

// gauntlet returns the files whose newest usable gauntlet observation says
// atomscan misjudged them: a good file detected, or a bad one passed. The
// newest observation is chosen before the test, so an old miss does not
// come back after a newer run shows it fixed. A review answers one
// observation (its evidence key) for good; a withdrawn good file is left out.
func (st *Store) gauntlet(ctx context.Context, n int, excluded [][]byte) ([]Candidate, error) {
	rows, err := st.pool.Query(ctx, `WITH ranked AS (
			SELECT g.run_id, g.sha256, g.label, v.status, v.evidence_key, v.payload, r.observed_at, r.metadata,
			       row_number() OVER (PARTITION BY g.sha256 ORDER BY r.observed_at DESC, g.run_id DESC) AS rank
			FROM gauntlet_results v
			JOIN gauntlet_samples g ON g.run_id = v.run_id AND g.sha256 = v.sha256
			JOIN gauntlet_runs r ON r.id = g.run_id
			WHERE v.scanner = 'ascan' AND v.status IN ('benign', 'detected') AND g.eligible AND r.observed_at <> ''
		)
		SELECT s.id, c.run_id, c.label, c.status, c.evidence_key, c.payload, c.observed_at, c.metadata
		FROM ranked c
		JOIN samples s ON s.sha256 = CASE WHEN c.sha256 ~ '^[0-9a-f]{64}$' THEN decode(c.sha256, 'hex') END
		LEFT JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = 1
		WHERE c.rank = 1 AND (a.outcome IS NULL OR a.outcome = 'ok') AND `+triageSettled+`
		  AND EXISTS (SELECT 1 FROM locations l WHERE l.sample_id = s.id)
		  AND (c.label <> 'good' OR NOT EXISTS (SELECT 1 FROM gauntlet_withdrawals w WHERE w.sha256 = c.sha256))
		  AND s.label NOT IN ('dual-use', 'inconclusive')
		  AND ((c.label = 'good' AND c.status = 'detected') OR (c.label = 'bad' AND c.status = 'benign'))
		  AND NOT EXISTS (SELECT 1 FROM reports p WHERE p.sample_id = s.id AND p.report_type = 'gauntlet'
		                  AND p.evidence_key = c.evidence_key)
		  AND s.sha256 <> ALL ($1::bytea[])
		ORDER BY c.observed_at, c.sha256 LIMIT $2`, excluded, n)
	if err != nil {
		return nil, fmt.Errorf("store: triage gauntlet: %w", err)
	}
	var (
		ids               []int64
		picks             = map[int64]*GauntletPick{}
		id                int64
		p                 GauntletPick
		payload, metadata string
	)
	_, err = pgx.ForEachRow(rows, []any{&id, &p.RunID, &p.Expected, &p.Status, &p.Key, &payload, &p.ObservedAt, &metadata}, func() error {
		pick := p
		pick.Payload, pick.Metadata = json.RawMessage(payload), json.RawMessage(metadata)
		ids, picks[id] = append(ids, id), &pick
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: triage gauntlet: %w", err)
	}
	return st.candidates(ctx, ids, picks)
}

// candidates reads what a worker needs for each file, in the order given.
func (st *Store) candidates(ctx context.Context, ids []int64, picks map[int64]*GauntletPick) ([]Candidate, error) {
	out := make([]Candidate, 0, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := st.pool.Query(ctx, `SELECT s.id, s.sha256, s.size_bytes, coalesce(s.file_type, ''), s.label::text,
			coalesce(s.label_source, ''), coalesce(n.name, ''), s.version, s.created_at, sc.scanned_at,
			coalesce(l.path, ''), coalesce(l.feed, ''), a.summary->'top'
		FROM unnest($1::bigint[]) WITH ORDINALITY AS c(id, ord)
		JOIN samples s ON s.id = c.id
		LEFT JOIN names n ON n.id = s.name_id
		LEFT JOIN scans sc ON sc.sample_id = s.id
		LEFT JOIN verdicts a ON a.sample_id = s.id AND a.scanner_id = $2
		LEFT JOIN LATERAL (SELECT path, feed FROM locations WHERE sample_id = s.id ORDER BY seen_at DESC, path LIMIT 1) l ON true
		ORDER BY c.ord`, ids, atomscan)
	if err != nil {
		return nil, fmt.Errorf("store: triage candidates: %w", err)
	}
	var (
		c       Candidate
		scanned *time.Time
		top     []byte
	)
	_, err = pgx.ForEachRow(rows, []any{
		&c.ID, &c.SHA256, &c.SizeBytes, &c.FileType, &c.Label, &c.LabelSource, &c.Name,
		&c.Version, &c.CreatedAt, &scanned, &c.Path, &c.Feed, &top,
	}, func() error {
		got := c
		got.CreatedAt = c.CreatedAt.UTC()
		if scanned != nil {
			got.ScannedAt = scanned.UTC()
		}
		if len(top) > 0 && json.Unmarshal(top, &got.Top) != nil {
			got.Top = nil // a malformed summary loses its findings, not the file
		}
		got.Gauntlet = picks[c.ID]
		out = append(out, got)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: triage candidates: %w", err)
	}
	return out, nil
}

// TriageReport is what a triage worker concluded about a file a queue
// handed it, filed under that queue's name (Type).
type TriageReport struct {
	Type        string
	Provider    string
	Content     string
	EvidenceKey string // a gauntlet review: the observation it answers
	SHA256      []byte
}

// ErrGauntletEvidence reports a gauntlet review naming an observation no
// published run holds for the file.
var ErrGauntletEvidence = errors.New("store: no such gauntlet evidence")

// FileReport records r. A gauntlet review answers its observation once:
// repeating it records nothing more. A report on a file hopper does not hold
// is ErrNotFound.
func (st *Store) FileReport(ctx context.Context, r TriageReport) error {
	if r.Type == "gauntlet" {
		var known bool
		if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM gauntlet_results
			WHERE sha256 = encode($1, 'hex') AND scanner = 'ascan' AND evidence_key = $2)`, r.SHA256, r.EvidenceKey).Scan(&known); err != nil {
			return fmt.Errorf("store: report: %w", err)
		}
		if !known {
			return ErrGauntletEvidence
		}
	}
	var held bool
	err := st.pool.QueryRow(ctx, `WITH s AS (SELECT id FROM samples WHERE sha256 = $1), r AS (
			INSERT INTO reports (sample_id, report_type, provider, content, evidence_key)
			SELECT id, $2, $3, $4, $5 FROM s
			ON CONFLICT DO NOTHING)
		SELECT EXISTS (SELECT 1 FROM s)`, r.SHA256, r.Type, r.Provider, r.Content, r.EvidenceKey).Scan(&held)
	switch {
	case err != nil:
		return fmt.Errorf("store: report: %w", err)
	case !held:
		return ErrNotFound
	default:
		return nil
	}
}
