package hopper

// triagequeues.go is the triage queue registry: the named selections cyclotron's
// workers pull from, and the depth counts an operator reads.
//
// A "queue" is nothing more than a parametrized SELECT over the samples table —
// for most, the newest top-level (parent='') misfiles whose stored label
// disagrees with cleave's verdict. Processing an item resolves the disagreement,
// so the same query naturally returns the next-newest work on the following
// pass: the queue drains itself. The exceptions are called out per queue below.
//
// The definitions live in hopper rather than in the consumer because everything
// they are made of already does: the Triage* selectors, the
// TriageFilter shape, and the drain predicates that anti-join a reports row
// named for the queue. That last one is why the split was untenable — hopper's
// triage SQL matches 'second'/'acquit'/'highest'/'lowest' literally, so the wire
// name was already a contract between the two systems, just an undeclared one.
//
// What deliberately does NOT live here is everything a consumer decides ABOUT a
// queue: its display name, its provider chain and tier, how many workers it
// runs, which outcomes file a drain report. Those are policy, they change on the
// consumer's cadence, and hopper has no opinion on them.

import (
	"context"
	"slices"
	"time"
)

// Queue is one triage queue. Select returns up to n candidates in the queue's
// order; the caller decides how many it can actually work.
//
// There is deliberately no separate depth predicate. A queue's depth is its own
// selection, run to [TriageDepthCap] and counted -- see [Queue.Count] -- because
// the alternative was a second hand-written spelling of every queue's
// membership, and the failure mode of a hand-copied predicate is a number that
// looks authoritative and has quietly stopped describing the queue it names.
// That is not hypothetical: the 2026-09-01 rightsizing added a freshness floor
// to the selectors and to six of the eight counts, and highest and lowest went
// on reporting the whole model/label disagreement corpus -- two orders of
// magnitude over their real population -- until 2026-09-02.
//
// Counting a selection costs what the selection costs. That is affordable
// because it is now bounded: every queue carries a freshness floor sized to hold
// it near a thousand rows, so the cap is a guard against a regression rather
// than a routine truncation.
//
// CountSelect overrides Select for that count. It is nil for most queues, and
// set for the three whose selection is deliberately not the population:
//
//   - highest and lowest bound each route to triagePerRouteK candidates, a
//     batching device that keeps one route from monopolizing a selection.
//     Counting through it reports the bound, so their count runs the same query
//     with that K lifted to the cap.
//   - stranded selects archives but is worked per member, so counting its
//     selection reports packages waiting rather than rulings waiting.
//
// Both cases keep the queue's predicate; only its shape changes. That is the
// line to hold if a fourth is ever added — a CountSelect that re-states
// membership is the drift this design exists to prevent.
type Queue struct {
	Select      func(ctx context.Context, db *DB, n int) ([]*Sample, error)
	CountSelect func(ctx context.Context, db *DB, n int) ([]*Sample, error)
	Name        string
}

// TriageDepthCap bounds a depth count. A queue at the cap reports the cap and
// capped=true; callers render that as "<cap>+".
//
// Sized for materializing rows, not for counting them: the count is a real
// selection, so the cap is the most Sample values a depth is willing to build.
// Comfortably above the ~1000 every queue's freshness floor is tuned to, and
// above the one queue deliberately left over it (bad, whose residual is real
// detection gaps rather than churn), so hitting it means something has
// regressed -- which is what an operator should read "10000+" as.
const TriageDepthCap = 10000

// Count reports how much work is waiting, for an operator surface, by running
// the queue's own selection to the cap and counting what comes back. capped
// reports that the queue reached the cap and the true population is larger.
func (q Queue) Count(ctx context.Context, db *DB) (n int64, capped bool, err error) {
	sel := q.CountSelect
	if sel == nil {
		sel = q.Select
	}
	rows, err := sel(ctx, db, TriageDepthCap)
	if err != nil {
		return 0, false, err
	}
	return int64(len(rows)), len(rows) >= TriageDepthCap, nil
}

// The grace windows the score- and evidence-ranked queues select against.
// Exported because they are operator-visible tuning, not internals: a consumer
// that renders "why is this queue empty" needs to say how long the wait is.
const (
	// SecondOpinionSettle is how long after a sample's most recent analysis the
	// second-opinion queue waits before re-judging it, so the first pass's
	// write-backs and relabels finish landing before a premium review spends
	// tokens on it.
	SecondOpinionSettle = 24 * time.Hour

	// AcquitGrace is how old a conviction must be before the acquit queue
	// questions it: long enough for threat feeds to corroborate a genuinely
	// malicious sample, so the queue only ever holds convictions the world has
	// had a fair chance to confirm.
	AcquitGrace = 72 * time.Hour

	// OutlierGrace holds the highest/lowest queues off anything newer than this.
	// Those two are score-ranked over the same rows good and bad walk
	// newest-first, so the age floor keeps the pairs working opposite ends of the
	// table instead of contending for the same per-sha tmp dirs. It also lets a
	// fresh sample's score settle — re-analysis and late sightings both move it —
	// before a premium review spends tokens on it.
	OutlierGrace = 48 * time.Hour

	// FalloutWindow bounds how far back the fallout queue reaches. Selection is
	// newest-first, so widening it only adds tail: the freshest gaps are always
	// worked ahead of older ones. Matches the 7 days the public fallout page
	// renders — the queue covers exactly what the page shows, and anything older
	// backfills through the ordinary queues.
	FalloutWindow = 7 * 24 * time.Hour

	// VersionDriftWindow bounds how far back version-drift reaches, and unlike
	// the grace windows above it exists for a hard performance reason.
	//
	// The queue's sibling test is a cross-row EXISTS, so it cannot live in a
	// partial index: the planner walks the candidate index in created_at order
	// and probes each row. When few candidates have a clean earlier release the
	// walk runs long, and on 2026-08-31 it ran past the API's 30s query timeout
	// on EVERY poll — 118 consecutive 500s, a queue that never once ran. The
	// window caps the walk at rows that can still be reached inside the budget.
	//
	// A week is also the right answer on merit: what this queue looks for is a
	// package compromised between releases, and the value of catching that
	// decays by the day. A drift first published a month ago has either been
	// caught by another queue or is already installed everywhere.
	VersionDriftWindow = 7 * 24 * time.Hour

	// FPTraitFreshness and the freshness floors below it are the mirror of the
	// grace windows above: those hold a queue OFF work that is too new, these
	// hold it off work whose stored verdict is too OLD. They exist to draw a
	// boundary between two systems rather than to tune a queue.
	//
	// A sample whose cleave_result predates the current traits is a RESCAN job:
	// hopper's own stale-traits tier walks those (see staleTraitsCandidatesPG),
	// re-analyzes them, and the fresh verdict either drops the row out of a
	// triage predicate or leaves it in on current evidence. Offering those rows
	// to cyclotron as triage instead makes the triage fleet the rescan tier: it
	// fetches the sample, spawns a scan, takes a git worktree and lands an empty
	// batch to rediscover what a rescan would have told it. Measured 2026-09-01,
	// that was 93-99% of every selection on discord, bad, fp-trait and popular —
	// 666 selections on discord to reach two LLM passes.
	//
	// traits_version would express this exactly, and is what the rescan tier
	// keys on. It cannot be used here: it is empty on 96% of rows analyzed in the
	// last three days, so a predicate on it would select a few thousand arbitrary
	// samples. analyzed_at is the coarse proxy, and the values differ per queue
	// because the populations age at very different rates — the bad-labelled
	// pools barely move for months, so they take a wide floor, while the
	// unconvicted pools turn over daily and take a narrow one.
	//
	// Each was chosen to hold its queue near 1000 rows, measured against
	// production on 2026-09-01. They are the sizing knob: widen one and its queue
	// grows roughly in proportion.
	FPTraitFreshness    = 24 * time.Hour
	DiscordFreshness    = 24 * time.Hour
	SuspiciousFreshness = 12 * time.Hour
	// HostileFreshness is deliberately equal to SuspiciousFreshness: the tiers are
	// one population re-cut by severity, so they age at the same rate and a
	// different floor on each would be an accident rather than a decision.
	// Separate constants only so either can be tuned without moving the other.
	HostileFreshness = 12 * time.Hour
	HighestFreshness = 3 * 24 * time.Hour
	PopularFreshness = 7 * 24 * time.Hour
	LowestFreshness  = 30 * 24 * time.Hour

	// BadFreshness is the one floor whose residual is not churn, and the only one
	// deliberately left above the ~1000 target. Its population is known malware
	// our rules do not convict, so every row surviving the floor is a real
	// detection gap: shrinking it further does not remove noise, it chooses which
	// malware to leave undetected. See the queue's comment in TriageQueues.
	//
	// A day holds ~7.3k (measured 2026-09-01). Reaching 1000 needs roughly a
	// 75-minute floor, and the curve there is steep -- 30m=511, 1h=529, 90m=1792,
	// 2h=2194 -- so anything under two hours reports where the rescan cycle
	// happens to be rather than how much detection debt exists, swinging 3x
	// between polls. The floor's job here is only to keep stale verdicts out
	// (they were 93% of this queue's selections); the size is a separate problem
	// and better solved by bounding what a poll RETURNS than by hiding rows.
	BadFreshness = 24 * time.Hour
)

// ReportCooldown is how long a queue's report parks a sample before it can be
// considered again, on top of requiring a re-analysis.
//
// Re-entry needs BOTH: the sample must have been re-analyzed since the report
// (r.created_at > analyzed_at), and the report must be older than this. Either
// alone lets a sample come round too easily -- a re-analysis on the same day
// re-admits work judged hours ago, and age alone re-admits work nothing has
// re-examined.
//
// The re-analysis half is standing in for "the traits changed". traits_version
// would say that directly and is what the rescan tier keys on, but it is empty
// on 96% of rows analyzed in the last three days (measured 2026-09-01), so a
// predicate over it would compare ” to ” and park everything forever. A
// re-analysis is the event that APPLIES current traits to a sample, so it is the
// materialised form of the same question and the one the data supports. Revisit
// if traits_version is ever backfilled.
const ReportCooldown = 72 * time.Hour

// staleTriageFilter builds the TriageFilter for a queue that walks
// least-recently-analyzed first and drains via a report row named for itself.
//
// MinAnalyzedAt is deliberately left zero. Bounding it would restrict the queue
// to rows whose verdict is recent enough to trust, but the only thing that
// refreshes a verdict is a re-scan, and the rescan tier reaches this population
// at roughly 1.4k/day against a 1.6M backlog — a floor would gate the queue's
// ~30/day on that, for no gain. The report drain covers the same ground from the
// other side: a stale row that current traits already catch is judged once,
// produces no edit, and is parked until something re-scans it.
func staleTriageFilter(queue string) TriageFilter {
	return queueFilter(queue, TriageFilter{Order: TriageStale})
}

// queueFilter stamps a queue's own name into ExcludeReportType. Every entry in
// the registry builds its filter through this, so the report anti-join is a
// property of being a queue rather than something each one opts into.
//
// It was an option once, and the three spellings that grew from that are the
// argument against it: some queues embedded a literal NOT EXISTS in their SQL,
// some passed ExcludeReportType, and six passed nothing at all and re-offered
// judged work forever. One helper means a new queue cannot be added without the
// guard, and TestEveryQueueExcludesItsOwnReport proves it rather than trusting
// the author to remember.
func queueFilter(queue string, f TriageFilter) TriageFilter {
	f.ExcludeReportType = queue
	return f
}

// TriageQueues is the registry. Keys are the wire names, which are load-bearing
// in ways a rename would silently break — they are the reports row type the
// review and stale queues drain through (the triage SQL matches them literally),
// and consumers derive relabel sources, metric job names and dashboard keys from
// them. Renaming one is a data migration, not a refactor.
// EVERY queue anti-joins a report named for itself, via ExcludeReportType.
// That is not each queue's drain -- most drain because the judgement changes
// something the selector reads -- it is the guard against a sample rotating
// between queues, or back into the same one, on evidence nobody has revisited.
// The anti-join carries `r.created_at > analyzed_at`, so a report parks a sample
// only until a rescan gives it a fresh verdict; it is a cooldown, not a
// tombstone. A queue added here without one re-offers work already judged.
var TriageQueues = map[string]Queue{
	// bad: bad-labeled samples cleave missed (false negatives) → write traits.
	"bad": {Name: "bad", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageBad(ctx, n, time.Now().Add(-BadFreshness), queueFilter("bad", TriageFilter{}))
	}},

	// The unconvicted pair (2026-08-30), which REPLACED good and new. Those two
	// split the same work by standing label — good-labeled files that trip
	// detection, unknown-labeled files that trip detection — and since
	// suspicious_count counts crit>=4 findings, `unknown AND suspicious_count>=1`
	// was exactly `unknown AND max_crit>=4`. So the old pair's union is this
	// pair's union, re-cut along the axis that decides what a mistake COSTS
	// instead of the axis of what we currently believe.
	//
	// Two reasons the severity cut is the better one. It lets the hostile tier
	// take a stronger provider chain than the suspicious tier, which the merged
	// queues could not express. And it puts benign-labeled and unlabelled
	// samples in the SAME batch: a queue that only ever shows a judge false
	// positives teaches it that loosening is always the answer, which is the
	// failure the highest queue's prompt already has to argue against.
	//
	// The standing label is not gone, it has moved — out of the queue's identity
	// and into the prompt as per-sample evidence.
	//
	// Both drain themselves: the findings dropping below the tier's bar removes
	// the row. Their -stale twins do not, and take the usual report park.
	"unconvicted-hostile": {Name: "unconvicted-hostile", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageUnconvictedHostile(ctx, n, time.Now().Add(-HostileFreshness),
			queueFilter("unconvicted-hostile", TriageFilter{Order: TriageRepair}))
	}},

	"unconvicted-suspicious": {Name: "unconvicted-suspicious", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageUnconvictedSuspicious(ctx,
			n, time.Now().Add(-SuspiciousFreshness), queueFilter("unconvicted-suspicious", TriageFilter{Order: TriageRepair}))
	}},

	"unconvicted-hostile-stale": {Name: "unconvicted-hostile-stale", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageUnconvictedHostile(ctx, n, time.Now().Add(-HostileFreshness), staleTriageFilter("unconvicted-hostile-stale"))
	}},

	"unconvicted-suspicious-stale": {Name: "unconvicted-suspicious-stale", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageUnconvictedSuspicious(ctx, n, time.Now().Add(-SuspiciousFreshness), staleTriageFilter("unconvicted-suspicious-stale"))
	}},

	// version-drift: this release fires, an earlier release of the same package
	// did not and is labelled good. Either the package was compromised between
	// releases or a rule started over-firing — indistinguishable from one file,
	// which is why the queue exists: the clean sibling gives the judge a diff.
	//
	// Self-draining, from either side: loosening the rule drops the row below the
	// floor, and convicting the package moves it out of the unconvicted pool.
	// Its depth, like second's and acquit's, used to be omitted because the
	// population is defined by a per-row sibling probe rather than a predicate
	// over samples, and counting it would have cost what the unbounded selector
	// cost — which is what took the queue down on 2026-08-31. It now has one,
	// because a depth is the selection and the selection is bounded:
	// VersionDriftWindow caps the walk, so the count pays the walk's cost and no
	// more. Read it as "candidates inside the window", which is the same thing
	// the queue hands out.
	"version-drift": {Name: "version-drift", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageVersionDrift(ctx, n, time.Now().Add(-VersionDriftWindow), queueFilter("version-drift", TriageFilter{}))
	}},

	// fp-trait: every sample in the batch fires the SAME over-firing trait — the
	// one appearing on the most benign-labelled samples in the recent window.
	//
	// The other queues hand a judge N unrelated false positives and ask for N
	// separate fixes. One bad rule produces thousands, so those are N passes
	// spent on what is really one edit. Clustering the batch on a single trait is
	// what makes the pattern legible, and it is the only queue here whose ranking
	// is a property of our RULES rather than of a sample.
	//
	// Newest-first within the chosen trait; the trait selection is the ranking.
	// Self-draining: loosening it drops its samples below the max_crit floor and
	// the next pass ranks whatever is worst then.
	"fp-trait": {Name: "fp-trait", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageFPTrait(ctx, n, time.Now().Add(-FPTraitFreshness), queueFilter("fp-trait", TriageFilter{}))
	}},

	// discord: our rule engine and our ML ensemble disagree about the same bytes
	// — one calls it hostile while the other is silent. Label-agnostic like
	// popular and fallout, because a detector conflict is a defect wherever it
	// lands; the standing label only decides WHICH detector is the suspect. See
	// triageDiscordWhere for the four readings.
	//
	// This is the only queue on the litmus_class axis that is about detection
	// quality: fallout also keys on class, but gates on being undescribed or
	// uncorroborated, which makes it an explanation queue.
	//
	// Self-draining: whichever detector was wrong gets fixed, the two agree, and
	// the row leaves. Newest-first — a conflict does not get more interesting
	// with age, and both arms are narrow enough that the head keeps moving.
	"discord": {Name: "discord", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageDiscord(ctx, n, time.Now().Add(-DiscordFreshness), queueFilter("discord", TriageFilter{}))
	}},

	// sighted: every non-bad sample covered by a malicious or suspicious ledger
	// sighting → verify the claim, writing traits when malicious. Exact version
	// claims only cover that release; a claim without a version covers the whole
	// package. Vulnerability claims stay out. The legacy sighted label is not
	// evidence and does not select work. A bad ruling drains via relabel and a
	// confirmed non-bad ruling via report. Its depth is the selection counted, so
	// it reports what the queue can actually hand out rather than the full
	// expansion of every broad package claim across the corpus — which is the
	// count that was too expensive to take, and the wrong number besides.
	"sighted": {Name: "sighted", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageSighted(ctx, n, queueFilter("sighted", TriageFilter{}))
	}},

	// second: good-labeled samples whose benign label an outside source disputes
	// (a trusted malware-hosting source, or 2+ independent sources) → re-judge
	// with a premium provider chain, write traits, and relabel when the model
	// overturns the label. Most reviews are expected to agree with the standing
	// label; SecondOpinionSettle keeps a just-analyzed sample from being
	// immediately second-guessed. Detection-tripping samples are excluded here,
	// not by the consumer: they are the good queue's set, and queue disjointness
	// is what lets workers share per-sha sample tmp dirs safely.
	//
	// Its population is evidence-ranked against the sightings ledger rather than
	// being a plain predicate over samples, so there was never a cheap count to
	// write. It has a depth now for the reason every queue does: the depth is the
	// selection, and there is always a selection.
	"second": {Name: "second", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageSecondOpinion(ctx, n, TrustedBadSources,
			time.Now().Add(-SecondOpinionSettle), queueFilter("second", TriageFilter{}))
	}},

	// highest: whole archives (good/unknown parents) containing a good-labeled
	// member the ensemble scores hostile, worst first → settle the label, then
	// loosen the traits driving the score. Those members pin each route's
	// operating point (a per-route threshold sits at the highest-scoring benign
	// in its slice), so the top of this queue is where reported recall is lost.
	// TriageHighest collapses hot members to their parent and returns the archive
	// itself, so the worker fetches and judges the whole package — provenance and
	// sibling files are what make the call cheap, and scoring a lone member out of
	// its archive throws both away. The whole-archive scan on upload also refreshes
	// every sibling's score for free.
	"highest": {Name: "highest", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageHighest(ctx,
			n, triagePerRouteK, now.Add(-OutlierGrace), now.Add(-MissingRetry), now.Add(-HighestFreshness), queueFilter("highest", TriageFilter{}))
	}, CountSelect: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		// Same query, both bounds lifted: the per-route K is a batching device
		// (see Queue.CountSelect), so counting through it would report ~routes*K
		// rather than the population those routes are drawn from.
		now := time.Now()
		return db.TriageHighest(ctx,
			n, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), now.Add(-HighestFreshness), queueFilter("highest", TriageFilter{}))
	}},

	// lowest: the mirror — bad-labeled samples the ensemble scores clean,
	// best-hidden first → settle the label, then write the traits that would
	// catch them. Judged per file, not per archive: members inherit "bad" from
	// their parent at explode time, so a chunk of this queue is inert content
	// that was never malicious, and relabelling those is as valuable as any
	// trait. That per-file granularity is why its drain keys on the member's own
	// sha while highest's keys on the root archive.
	"lowest": {Name: "lowest", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageLowest(ctx,
			n, triagePerRouteK, now.Add(-OutlierGrace), now.Add(-MissingRetry), now.Add(-LowestFreshness), queueFilter("lowest", TriageFilter{}))
	}, CountSelect: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		// See highest's.
		now := time.Now()
		return db.TriageLowest(ctx,
			n, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), now.Add(-LowestFreshness), queueFilter("lowest", TriageFilter{}))
	}},

	// stranded: good-labeled members with real findings inside CONVICTED
	// archives — benign labels inherited before the parent's conviction and
	// never individually reviewed. Unit of work is the archive (context);
	// verdicts and the drain are PER MEMBER, so an archive resurfaces until every
	// qualifying member has been judged.
	//
	// The second queue after highest/lowest to need a CountSelect, and for a
	// different reason: not a batching bound, but a unit mismatch. Its selection
	// is archives and its work is members, so counting the selection reports how
	// many packages are waiting rather than how many rulings are — 11 against 68,
	// measured 2026-09-02. Counting members is also 25x cheaper (0.6s against
	// 17.3s); see TriageStrandedPopulation for why the archive shape is the
	// expensive one.
	"stranded": {Name: "stranded", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageStranded(ctx, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), queueFilter("stranded", TriageFilter{}))
	}, CountSelect: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		now := time.Now()
		return db.TriageStrandedPopulation(ctx, n, now.Add(-OutlierGrace), now.Add(-MissingRetry), queueFilter("stranded", TriageFilter{}))
	}},

	// popular: samples from a ranked package whose worst finding is suspicious
	// or hostile (the suspiciousCrit floor), worst-ranked package first.
	// Deliberately NOT every sample that trips detection: "notable" findings are
	// worth recording and not worth this queue, and on popular packages they are
	// 92% of the population — a backlog measured in months, spent on ordinary
	// behaviour, with every other queue stood down behind it.
	//
	// Label-agnostic on purpose — every other queue selects on what we believe
	// about a sample; this one selects on what a mistake would cost. A false
	// positive on a package a million people install is worth a slot whether it
	// is filed good, unknown, or bad, and it is worth far more than the same
	// finding on a package nobody imports. Rank ordering is the point: a miss on
	// rank 3 outranks a miss on rank 900.
	//
	// Populated by poppy, which publishes each ecosystem's ranking on every daily
	// catalog refresh. Like the -stale queues it does not self-drain — judging a
	// sample does not remove it from the marked set — so it takes the same
	// ExcludeReportType drain: a completed judgement parks the sample until a
	// re-analysis makes the question worth asking again.
	//
	// popular_packages must be present for this queue to return anything. On a
	// logical replica that means the table has to be in REPLICATED_TABLES —
	// migration creates it empty either way, so an unpublished table reads as a
	// permanently drained queue rather than as an error.
	"popular": {Name: "popular", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriagePopular(ctx, n, time.Now().Add(-PopularFreshness), staleTriageFilter("popular"))
	}},

	// The -stale queues: the same populations as new/good, ranked
	// least-recently-analyzed first instead of newest-added first. Their reason
	// to exist is that the newest-first queues cannot reach the backlog — while
	// arrivals outpace triage the cursor never descends past the last few days,
	// which leaves ~99% of each population permanently unexamined. Ordering by
	// analyzed_at rather than created_at also targets the right thing: a row's
	// queue membership is whatever its last scan computed, so the least recently
	// analyzed rows are the ones whose verdict rests on the oldest trait set.
	//
	// Unlike their newest-first counterparts these do not self-drain. A
	// newest-first queue is pushed along by fresh arrivals, so a sample nothing
	// can be done about sinks on its own; a stale queue's head does not move,
	// and without a drain the same unfixable row would be re-selected forever.
	// Hence ExcludeReportType: a completed judgement files a "<queue>" report
	// that parks the sample until it is re-analyzed, at which point the verdict
	// is new and the question is worth asking again.
	//
	// There is deliberately no bad-stale. Its product would be traits that catch
	// OLD malware — a false-negative fix on samples that are no longer
	// circulating, which is not worth a batch slot. False POSITIVES in old
	// samples are, because a wrong detection keeps costing recall for as long as
	// it stands: an over-firing trait caps every route whose threshold sits at
	// its highest-scoring benign. The label-hygiene half of what bad-stale would
	// have done (bad-labeled files that are really inert) is already covered by
	// lowest, which is score-ranked and so reaches old samples natively.
	// (good-stale and new-stale retired 2026-08-30; their populations are the
	// unconvicted pair's -stale twins, registered above with the pair itself so
	// each severity tier's two orderings sit together.)

	// acquit: the second queue's mirror — bad-labeled samples whose conviction
	// no outside evidence has ever supported (provenance shows a registry pull,
	// not a malware-feed download; no sighting from anyone) → re-judge the
	// conviction with a premium chain. Most convictions stand; a wrongful one is
	// relabeled good (it was poisoning trait training) and its over-tight traits
	// loosened. Detection-gap samples are excluded here — they are the bad
	// queue's set, same disjointness rule as second vs good.
	//
	// Like second, its population is defined by the ABSENCE of a sighting, which
	// is not a countable predicate over samples alone — so its depth is the one
	// number that always exists, its own selection counted.
	"acquit": {Name: "acquit", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageAcquit(ctx, n, time.Now().Add(-AcquitGrace), queueFilter("acquit", TriageFilter{}))
	}},

	// fallout: litmus-hostile samples (class 2 — the public fallout page's
	// population) that are UNDESCRIBED or UNCORROBORATED. Undescribed is the
	// original population: no LLM interpretation, because the reasoning pass
	// never ran (arrivals outpace the new queue, which ranks a litmus-hostile
	// sample no higher than any other suspicious unknown) or it failed and
	// stored only an error. Uncorroborated is the second: we call it hostile and
	// no outside source has ever cited it, which on this page is the more common
	// gap by an order of magnitude (229 of 337 over a week, against 11
	// undescribed — and every undescribed sample was also uncorroborated).
	//
	// One queue for both because they are one population worked by one pass. The
	// judgement it produces answers whichever gap applied: the write-back's
	// interpret pass stores the rationale a described-nothing sample lacks, and
	// the verdict itself settles whether a hostile call nobody else made still
	// stands.
	//
	// Uniquely, its population spans label pools (the page filters on
	// classification, not label), so it overlaps new/bad/good rather than
	// partitioning against them — a consumer's claim set is what keeps two queues
	// off the same sample.
	//
	// Two drains: llm_result landing removes an undescribed row from the
	// selector, and a completed judgement files a "fallout" report (permanent
	// anti-join) which is the only thing that drains an uncorroborated one —
	// corroboration is not ours to produce. The permanent park also covers a
	// sample whose interpret pass errors (large renders overflow the endpoint),
	// which would otherwise churn through the window.
	//
	// The undescribed/uncorroborated disjunction spans the sightings ledger, so
	// there is no single predicate to count — but there is a selection, and that
	// is what its depth counts, bounded by FalloutWindow.
	"fallout": {Name: "fallout", Select: func(ctx context.Context, db *DB, n int) ([]*Sample, error) {
		return db.TriageFallout(ctx, n, time.Now().Add(-FalloutWindow), queueFilter("fallout", TriageFilter{}))
	}},
}

// TriageQueueNames returns every registered queue name, sorted.
//
// Sorted because TriageQueues is a map and Go randomizes map iteration; without
// it, a consumer's worker start order and every log line listing queues would
// vary per process. It is also the one list a consumer should validate its own
// per-queue policy tables against, so that adding a queue here fails that
// consumer's completeness test rather than silently getting a default.
func TriageQueueNames() []string {
	names := make([]string, 0, len(TriageQueues))
	for name := range TriageQueues {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
