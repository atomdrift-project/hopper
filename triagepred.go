package hopper

// triagepred.go holds each triage queue's membership predicate: the WHERE that
// says what is in the queue, in one place per queue, for every statement that
// has to agree about it.
//
// There are more of those than there look to be. A queue's predicate is read by
// its Postgres selector, by its SQLite mirror, and by the partial index that
// makes the selector affordable -- and until 2026-09-02 it was also read by a
// separate depth count, which is where this file got its old name and its old
// job. That count is gone: a depth is now the queue's own selection run to a cap
// and counted (see Queue.Count), because a second hand-written spelling of a
// queue's membership is a number that looks authoritative and quietly stops
// describing the queue it names. It did exactly that to highest and lowest.
//
// What remains here is the half that genuinely cannot be shared with a
// selector's SQL: a partial index predicate has to be a literal string, and it
// has to be IMMUTABLE, so it can hold a queue's population but never its
// freshness floor. Hence the split each queue below is written in -- a Pop half
// the index is built from, and a Where half that is the Pop plus `analyzed_at >
// %s`. The %s rather than $1 or ? is because the two dialects number
// placeholders differently and only the caller knows where in its own argument
// list the floor lands.
//
// The two score-ranked queues are the exception and live in hopper.go beside the
// constants that bound them, because their predicates are functions of a table
// alias rather than constants -- see triageHighestWhere.

import "strconv"

// The shared population predicates. Each is the exact WHERE its Triage*
// selector uses, so the two cannot drift: the selector and the count read the
// same constant.
//
// Only triageNewWhere* is per-dialect, because SQLite has no LIKE-with-% path
// prefix idiom in use here — the selectors have always spelled it GLOB.
const (
	// The detection bar is a CONVICTION bar, not a noticed-anything bar: this
	// queue is the false negatives, and a bad-labelled sample our rules score at
	// 1 -- or at 4 with a lone suspicious finding -- is still one we failed to
	// call malware. Those are the misses with a partial signal already present,
	// which is the cheapest kind to write a trait for, so narrowing to max_crit=0
	// would drop the most tractable half of the queue's own purpose.
	//
	// Bounded by the freshness floor alone (BadFreshness), which is a statement
	// about verdict age rather than about what counts as a miss. Takes one
	// placeholder.
	triageBadPop = `label = 'bad' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND max_crit < 5 AND suspicious_count < 2`

	// triageBadWhere is triageBadPop plus the freshness floor. The floor is relative to
	// now(), so it cannot live in a partial index predicate (Postgres requires
	// an immutable one) -- the indexes below carry analyzed_at as a KEY instead
	// and are built from triageBadPop, which keeps them in step with the half that can
	// be indexed.
	triageBadWhere = triageBadPop + `
	   AND analyzed_at > %s`

	triageGoodWhere = `label = 'good' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND (max_crit >= 5 OR suspicious_count >= 2)`

	// The unconvicted pair: samples nothing has convicted (label IN
	// ('good','unknown')) that our own RULE ENGINE flags, split by the severity
	// of that flag. Together they are exactly the old good + new populations —
	// suspicious_count counts crit>=4 findings, so the old
	// `unknown AND suspicious_count >= 1` was `unknown AND max_crit >= 4` — but
	// split on the axis that decides how much a mistake costs rather than on the
	// standing label. The label is not the queue's identity here; it rides into
	// the prompt as per-sample evidence, which is what lets one batch mix
	// benign-labeled false positives with unlabeled samples that need traits
	// ADDED. A queue that only ever shows a judge false positives teaches it to
	// loosen.
	//
	// The two are disjoint (max_crit >= 5 vs max_crit = 4) and their union is
	// the old pair's union exactly, so the split costs no coverage.
	// Takes one placeholder: the analyzed_at freshness floor (HostileFreshness).
	triageUnconvictedHostilePop = `label IN ('good', 'unknown') AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND max_crit >= 5`

	// triageUnconvictedHostileWhere is triageUnconvictedHostilePop plus the freshness floor. The floor is relative to
	// now(), so it cannot live in a partial index predicate (Postgres requires
	// an immutable one) -- the indexes below carry analyzed_at as a KEY instead
	// and are built from triageUnconvictedHostilePop, which keeps them in step with the half that can
	// be indexed.
	triageUnconvictedHostileWhere = triageUnconvictedHostilePop + `
	   AND analyzed_at > %s`

	// The suspicious tier's count bar is conditional on the label, because one
	// suspicious finding means different things on either side of it: on a file
	// we have already judged benign it is within policy (a benign sample is
	// allowed one suspicious finding if it genuinely does something unusual), so
	// it takes two to be worth a pass; on an unlabeled file it is the whole
	// reason to look. Without the label arm this queue would silently drop the
	// old new queue's weakest-but-largest slice.
	// The label arm is gone: the count bar is now unconditional. Spelled >= 2
	// rather than > 1 -- identical on an integer column, but Postgres will not
	// prove "> 1" implies the partial index's ">= 2", so the > form silently
	// stopped matching idx_samples_unconvicted_susp_repair and cost a seq scan. Dropping it
	// stops triaging unlabelled files carrying a single suspicious finding --
	// the old new queue's weakest-but-largest slice, and the reason this
	// population would not fit under any size cap. Deliberate coverage loss,
	// taken because the slice is also the least likely to repay a pass.
	// Takes one placeholder: the analyzed_at freshness floor (SuspiciousFreshness).
	triageUnconvictedSuspiciousPop = `label IN ('good', 'unknown') AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND max_crit = 4 AND suspicious_count >= 2`

	// triageUnconvictedSuspiciousWhere is triageUnconvictedSuspiciousPop plus the freshness floor. The floor is relative to
	// now(), so it cannot live in a partial index predicate (Postgres requires
	// an immutable one) -- the indexes below carry analyzed_at as a KEY instead
	// and are built from triageUnconvictedSuspiciousPop, which keeps them in step with the half that can
	// be indexed.
	triageUnconvictedSuspiciousWhere = triageUnconvictedSuspiciousPop + `
	   AND analyzed_at > %s`

	// discord: our two detectors disagree about the same bytes. The rule engine
	// speaks through max_crit and the ML ensemble through litmus_class, and a
	// file where one screams and the other is silent is a defect in whichever is
	// wrong — which is why this is deliberately label-agnostic, like popular and
	// fallout. The standing label picks the reading rather than the population:
	//
	//	good    + rules hostile, ML benign -> a rule is over-firing (FP)
	//	good    + rules silent, ML hostile -> the ensemble is over-firing (FP)
	//	bad     + rules hostile, ML benign -> an ML training gap
	//	bad     + rules silent, ML hostile -> a rule gap
	//	unknown + either                   -> classify, and the disagreement
	//	                                      says which detector to trust
	//
	// One selector, four readings, and it closes the litmus_class axis that
	// nothing but fallout touches — and fallout gates on being undescribed or
	// uncorroborated, so it is an explanation queue, not a detector-conflict one.
	//
	// litmus_class IS NOT NULL excludes rows the ensemble has never scored:
	// silence from a detector that never ran is not disagreement. The column is
	// nullable with a backfill still healing older rows, so without this the
	// queue would fill with samples nobody has an ML opinion about.
	// Per-dialect, like triageNewWhere*: litmus_class is a Postgres-only
	// materialized column (a trigger derives it there), so SQLite recomputes it
	// from litmus_result with the same formula. The PG side additionally guards
	// litmus_class IS NOT NULL — the column is nullable with a backfill still
	// healing older rows, and silence from a detector that never ran is not
	// disagreement. On SQLite the expression always yields a value, so the
	// equivalent guard is on litmus_result itself.
	triageDiscordPopPG = `cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND litmus_result IS NOT NULL AND litmus_class IS NOT NULL
		   AND ((max_crit >= 5 AND litmus_class = 0) OR (max_crit < 4 AND litmus_class = 2))`

	// triageDiscordWherePG is triageDiscordPopPG plus the freshness floor. That
	// floor is relative to now(), so it cannot live in a partial index predicate
	// -- Postgres requires an immutable one -- which is why the index is built
	// from the Pop half and carries analyzed_at as a KEY instead.
	triageDiscordWherePG = triageDiscordPopPG + `
		   AND analyzed_at > %s`

	// The sighted queue is derived from the sightings ledger, not from the
	// legacy sighted label. A package claim applies either to the exact stored
	// version named by affected, or to every version when affected is empty.
	// Digest claims name bytes and therefore need no version arm. Malicious and
	// suspicious claims both need adjudication; vulnerability records describe a
	// legitimate package's security defect and do not belong in a malware queue.
	triageSightedWhere = `label != 'bad' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND NOT EXISTS (SELECT 1 FROM reports r
		                   WHERE r.sha256 = samples.sha256 AND r.report_type = 'sighted')`

	triageNewWherePG = `label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND suspicious_count >= 1 AND path NOT LIKE 'review/%'`

	triageNewWhereSQLite = `label = 'unknown' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
		triageServablePathSQL + `
		   AND suspicious_count >= 1 AND path NOT GLOB 'review/*'`
)

// triageSightedMatchCTE deliberately starts from the comparatively small
// malware-relevant ledger slice and joins it into the indexed sample identities.
// Starting at samples would make every sighted poll probe the ledger once for
// each row in the full non-bad corpus. The UNION ALL keeps the digest and
// package index lookups independent; latest_sightings then collapses multiple
// sources and a possible digest+PURL double match to one candidate and its
// newest evidence.
const triageSightedMatchCTE = `WITH review_sightings AS (
		SELECT subject, affected, first_seen FROM sightings
		 WHERE claim IN ('malicious', 'suspicious')
	), matching_sightings AS (
		SELECT sm.sha256 AS matched_sha, s.first_seen AS sighted_at
		  FROM review_sightings s JOIN samples sm ON sm.sha256 = s.subject
		UNION ALL
		SELECT sm.sha256 AS matched_sha, s.first_seen AS sighted_at
		  FROM review_sightings s JOIN samples sm ON sm.purl_base = s.subject
		 WHERE sm.purl_base != ''
		   AND (s.affected = '' OR s.affected = sm.version)
	), latest_sightings AS (
		SELECT matched_sha, max(sighted_at) AS sighted_at
		  FROM matching_sightings GROUP BY matched_sha
	)
`

// triagePopularWhere is a var rather than a const because it embeds
// suspiciousCrit, and spelling that bound as a SQL literal here would put the
// number in two places — the one arrangement guaranteed to drift the day
// somebody retunes the floor.
// fp-trait: the good-labelled half of the unconvicted pool, restricted to
// rows carrying a derived top_traits list. Deliberately good-ONLY, unlike the
// unconvicted pair: this queue ranks by which of OUR RULES produces the most
// false positives, and an unlabelled sample firing a trait is not evidence of
// one. max_crit >= 4 rather than the pair's split bars, because a trait's
// over-firing is worth counting at either severity.
//
// It overlaps both unconvicted tiers on purpose — same rows, different
// question. popular and fallout already select across other queues'
// populations for the same reason, and the consumer's process-wide claim set
// is what keeps two workers off one sample.
// Takes one placeholder: the analyzed_at freshness floor (FPTraitFreshness).
// Spelled %s rather than $1/? because the two dialects number differently and
// the callers know where in their own argument list it lands -- the same shape
// countScored uses.
var triageFPTraitPop = `label = 'good' AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
	triageServablePathSQL + `
	   AND max_crit >= ` + strconv.Itoa(suspiciousCrit) + `
	   AND top_traits IS NOT NULL AND top_traits <> ''`

// triageFPTraitWhere is triageFPTraitPop plus the freshness floor. The floor is relative to
// now(), so it cannot live in a partial index predicate (Postgres requires
// an immutable one) -- the indexes below carry analyzed_at as a KEY instead
// and are built from triageFPTraitPop, which keeps them in step with the half that can
// be indexed.
var triageFPTraitWhere = triageFPTraitPop + `
	   AND analyzed_at > %s`

// triagePopularWhere is a var for the same reason: an embedded threshold.
// version-drift: an unconvicted sample that fires, from a package where an
// EARLIER version is labelled good and fires nothing. Either the package was
// compromised between releases, or the detection is new and wrong — and the
// clean sibling is what makes the question answerable, because it hands the
// judge a diff instead of a lone file to reason about.
//
// Ordering is by created_at rather than by parsed version. Version comparison
// across npm, PyPI, Alpine and Arch is a rabbit hole with no shared grammar, and
// "an earlier release of this package was clean" is what the queue actually
// means; arrival order answers that without inventing a comparator.
//
// The sibling probe is an EXISTS on purl_base, which idx_samples_purl_base
// serves, and a package has few versions — so the probe is a handful of rows per
// candidate rather than a join across the corpus.
// triageVersionDriftCandidates is version-drift's candidate side: everything
// except the clean-sibling test, which is a cross-row EXISTS and cannot live in
// a partial index. This is what idx_samples_version_drift_newest is built from.
//
// The sibling test is applied OUTSIDE, to a bounded slice of these — see
// versionDriftProbeBudget. It is a per-row probe with a low hit rate, so its
// cost scales with how many candidates are walked, not with how many match. A
// created_at window alone does not bound that: bounding time bounds the
// population, and 2026-08-31 showed a week of arrivals is still far more than
// the query budget allows (118 consecutive 30s timeouts, then more after the
// window landed). Only capping the number of probes bounds the work.
var triageVersionDriftCandidates = `label IN ('good', 'unknown') AND cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
	triageServablePathSQL + `
	   AND max_crit >= ` + strconv.Itoa(suspiciousCrit) + `
	   AND purl_base <> ''`

// versionDriftCandCols is the bounded candidate projection. Every column is
// aliased because the outer query selects a bare column list from samples and
// joins this back to it: an unaliased id is ambiguous there. The same shape bit
// fp-trait first, which is why both now spell it out.
const versionDriftCandCols = `id AS cand_id, sha256 AS cand_sha, purl_base AS cand_purl, created_at AS cand_created`

// versionDriftSiblingExists is the clean-earlier-release test, correlated
// against the bounded candidate set rather than against samples directly.
// p.purl_base <> ” is redundant against the equality above — cand_purl is never
// empty — but it is what makes idx_samples_clean_release applicable. Without it
// the planner cannot see that the probe's population is the 150k clean releases
// that HAVE a purl rather than all 14.5M clean benign samples, so it bitmap-scans
// the lot and hash-joins. That mis-shape, not the probe count, is what kept the
// queue at 25s+ after both earlier attempts to bound it.
var versionDriftSiblingExists = `EXISTS (SELECT 1 FROM samples p
	                WHERE p.purl_base = cand.cand_purl AND p.purl_base <> ''
	                  AND p.sha256 <> cand.cand_sha
	                  AND p.label = 'good' AND p.cleave_result IS NOT NULL AND p.skip = ''
	                  AND p.max_crit < ` + strconv.Itoa(suspiciousCrit) + `
	                  AND p.created_at < cand.cand_created)`

// cleanReleaseIndexPred is the probe's population: a benign-labelled release that
// trips nothing and can be named by PURL. Shared with the migration so the index
// predicate cannot drift from the query's.
var cleanReleaseIndexPred = `label = 'good' AND max_crit < ` + strconv.Itoa(suspiciousCrit) +
	` AND cleave_result IS NOT NULL AND skip = '' AND purl_base <> ''`

// Raised from suspicious to HOSTILE, and given a freshness floor. Popularity
// already makes this the queue the whole fleet stands down for, so its bar
// should be what justifies that: a widely-installed package our rules call
// hostile is either a live supply-chain compromise or a false positive about to
// hit a great many people. A merely suspicious finding on a popular package is
// neither, and it was most of the population.
//
// Takes one placeholder: the analyzed_at freshness floor (PopularFreshness).
var triagePopularPop = `cleave_result IS NOT NULL AND parent = ''` + triageServablePathSQL + `
		   AND skip != 'conflict'
		   AND max_crit >= 5
		   AND purl_base != ''
		   AND EXISTS (SELECT 1 FROM popular_packages p WHERE p.purl_base = samples.purl_base)`

// triageDiscordWhereSQLite mirrors [triageDiscordWherePG] with the class
// expression inlined. A var rather than a const because it is built from
// litmusClassSQLiteInline.
var triageDiscordPopSQLite = `cleave_result IS NOT NULL AND parent = '' AND skip = ''` +
	triageServablePathSQL + `
	   AND litmus_result IS NOT NULL
	   AND ((max_crit >= 5 AND ` + litmusClassSQLiteInline + ` = 0)
	        OR (max_crit < 4 AND ` + litmusClassSQLiteInline + ` = 2))`

// triageDiscordWhereSQLite is the SQLite mirror, same split.
var triageDiscordWhereSQLite = triageDiscordPopSQLite + `
	   AND analyzed_at > %s`

// triagePopularWhere is triagePopularPop plus the freshness floor. The floor is relative to
// now(), so it cannot live in a partial index predicate (Postgres requires
// an immutable one) -- the indexes below carry analyzed_at as a KEY instead
// and are built from triagePopularPop, which keeps them in step with the half that can
// be indexed.
var triagePopularWhere = triagePopularPop + `
	   AND analyzed_at > %s`
