package hopper

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Basis is how a source arrived at a claim: what kind of thing the claim is,
// not what it licenses anyone to do about it.
//
// Mirrored from parallax, which owns the judgement and stamps it onto each row
// as the claim is recorded — the way Operator already arrives with the claim
// rather than from a table here that has to be kept in step with one somewhere
// else. hopper cannot ask parallax directly: everything imports hopper, and
// parallax is a private module, so a dependency here would make hopper
// unbuildable for anyone without credentials. The fact travels with the data
// instead, which is the better shape regardless — a row can still explain
// itself after the policy that read it has changed.
//
// This is the same mirroring [SightingClaim] does of parallax.Claim, for the
// same reason.
type Basis string

const (
	// BasisPredicted means a detector or a model fired and nobody adjudicated
	// the result. The default, and the weakest kind of claim: a detector
	// believed on its own promotes its own false positives unopposed.
	BasisPredicted Basis = "predicted"
	// BasisHosted means the source holds the artifact as malware. A corpus
	// serving the bytes is not predicting anything.
	BasisHosted Basis = "hosted"
	// BasisReviewed means a person adjudicated the report before publication.
	BasisReviewed Basis = "reviewed"
)

// Firsthand reports whether the claim is a finding rather than a guess.
//
// An unrecognized basis — a row written by a producer newer than this build —
// reads as a guess. Believing a value we do not understand is the failure that
// costs something; disbelieving one costs a rung on the ladder.
func (b Basis) Firsthand() bool { return b == BasisHosted || b == BasisReviewed }

// Confidence is how much a body of outside claims justifies treating a subject
// as malware.
//
// Ordinal, not a probability. We have no calibration data that would make a
// percentage anything but false precision, and a float invites tuning by feel
// that no test can hold still. The rungs are the ladder itself, named once, so
// that promoter asking "is this enough to promote" and /v1/lookup asking "what
// level does this justify" are reading one judgement rather than two that drift.
type Confidence int

const (
	// NoClaim means nothing outside has made a malicious claim about the whole
	// subject. Not the same as "believed clean": nobody may have looked.
	NoClaim Confidence = iota
	// Weak is one operator, and it only predicts.
	Weak
	// Moderate is one operator that holds the artifact as malware.
	//
	// Below Reviewed deliberately. A corpus accepts what people submit to it;
	// curation is real but light, and presence means "somebody filed this as
	// malware" rather than "somebody confirmed it". The claim is still
	// firsthand — nobody is predicting anything about bytes they hold — which
	// is what puts it above a detector's guess.
	Moderate
	// Strong is one operator whose report a person adjudicated before it was
	// published.
	Strong
	// Corroborated is two independent operators.
	//
	// Above any single voice deliberately: two unrelated parties reaching the
	// same conclusion is stronger than one party reaching it carefully,
	// because the failure modes that produce a false positive are usually the
	// one party's own.
	Corroborated
	// Conclusive is three or more independent operators.
	Conclusive
)

func (c Confidence) String() string {
	switch c {
	case Weak:
		return "weak"
	case Moderate:
		return "moderate"
	case Strong:
		return "strong"
	case Corroborated:
		return "corroborated"
	case Conclusive:
		return "conclusive"
	case NoClaim:
		return "none"
	default:
		return "confidence(" + strconv.Itoa(int(c)) + ")"
	}
}

// Assessment is what the ledger says about one subject, and how much of it we
// believe.
//
// Every count that produced Confidence is carried. A score you cannot take
// apart is one you cannot debug, and — since this one can end in somebody's
// install being refused — one you cannot defend either.
type Assessment struct {
	// Strongest is the best-supported basis among the counted operators, and
	// what separates one corpus holding the bytes from one adjudicated report:
	// they reach different levels.
	//
	// Field order here is chosen for alignment rather than reading order: the
	// two pointer-bearing fields sit together at the front so the GC scans 24
	// bytes rather than 32.
	Strongest Basis
	// Operators that made a malicious claim covering the whole subject, sorted.
	// Operators, not sources: one vendor's three feeds are one voice, and osv
	// and ossf publish the same corpus.
	Operators []string
	// Firsthand is how many of those operators claim a finding rather than a
	// guess. See [Basis].
	Firsthand int
	// Scoped is how many malicious claims named specific versions instead of
	// the subject as a whole. Reported, never counted: resolving a range needs a
	// registry we may not have, and a caller blocking installs must not convict
	// 2.0.0 because 1.4.4 was flagged. gauntlet, building a benchmark cohort,
	// can afford the permissive reading and applies its own.
	Scoped int
	// Suspicious is how many claims stopped short of malice. Recorded so a
	// consumer can see them, never counted toward Confidence.
	Suspicious int
	Confidence Confidence
}

// Assess folds one subject's sightings into an Assessment.
//
// Pure: no I/O, no clock, no source table. The same rows therefore score
// identically whether they arrived from this ledger or from a live parallax
// lookup a producer converted and appended — which is what lets promoter union
// its live detections with the stored ones and ask a single question.
//
// Claims from sources we run ourselves must never reach here. That is enforced
// where it can be — at the producers, which hold parallax.Info and know a
// source's Standing — because a benchmark that seeds its own ground truth
// proves only that it agrees with itself, and two co-firing engines of ours
// could erase their shared false positive from the next run.
func Assess(sightings []Sighting) Assessment {
	// Folded on operator before counting, so volume from one voice cannot
	// climb the ladder. Value is the strongest basis that operator ever
	// claimed: a source that both hosts bytes and publishes a reviewed report
	// is credited with the stronger of the two, never the weaker.
	strongest := make(map[string]Basis, len(sightings))
	a := Assessment{}
	for i := range sightings {
		s := &sightings[i]
		switch s.Claim {
		case ClaimSuspicious:
			a.Suspicious++
			continue
		case ClaimMalicious:
		default: // ClaimVulnerable and anything unrecognized
			// A vulnerability is the opposite kind of fact: the package is
			// legitimate and some releases are not. Counting it as malware is
			// how one old advisory marked every clean version of an advised
			// package as externally disputed.
			continue
		}
		if !coversEveryRelease(s) {
			a.Scoped++
			continue
		}
		op := s.Operator
		if op == "" {
			op = s.Source
		}
		if op == "" {
			continue
		}
		// Inserted on first sight, then raised. A plain `>` compare would
		// never insert a predicted-only operator at all: its rank equals the
		// zero value's, so the operator would vanish from the count and a feed
		// everything currently reports as `predicted` would score NoClaim.
		if cur, seen := strongest[op]; !seen || rank(s.Basis) > rank(cur) {
			strongest[op] = s.Basis
		}
	}

	a.Operators = make([]string, 0, len(strongest))
	for op, basis := range strongest {
		a.Operators = append(a.Operators, op)
		if basis.Firsthand() {
			a.Firsthand++
		}
		if rank(basis) > rank(a.Strongest) {
			a.Strongest = basis
		}
	}
	slices.Sort(a.Operators)

	// Corroboration outranks any single voice, however good; below that the
	// rung is decided by what KIND of claim the lone operator made.
	switch n := len(a.Operators); {
	case n >= 3:
		a.Confidence = Conclusive
	case n == 2:
		a.Confidence = Corroborated
	case n == 1 && a.Strongest == BasisReviewed:
		a.Confidence = Strong
	case n == 1 && a.Strongest == BasisHosted:
		a.Confidence = Moderate
	case n == 1:
		a.Confidence = Weak
	default:
		a.Confidence = NoClaim
	}
	return a
}

// AllVersions is the canonical way a source says "every release of this
// package is malware".
//
// It is what aikido's own API publishes for a package that exists only to be
// malware, and parallax carries it through unchanged, so the spelling is the
// feed's rather than ours.
//
// The empty string is NOT the same claim. Empty means nobody told us the scope
// — the source published none, or a producer lost it — and those are opposite
// facts that wore one spelling until now. Only [AllVersions] convicts every
// release; see [coversEveryRelease].
//
// Chosen over a word like "all" because the code that already parses version
// constraints reads it correctly without being taught: "*" is the semver range
// meaning "any", while "all" would be compared as a literal version string and
// match only a release named "all".
const AllVersions = "*"

// coversEveryRelease reports whether a claim applies to the subject as a whole
// rather than to particular versions of it.
//
// A digest names exact bytes, which have no versions, so a digest claim always
// covers its subject entirely however Affected is spelled.
//
// A package claim must say [AllVersions]. An empty Affected is NOT that: it
// means the scope is unknown — the source published none, or a producer lost it
// on the way in — and convicting every release of a real package on a field
// nobody filled is how pkg:pypi/num2words@0.5.14 was graded hostile while
// every source that named versions named 0.5.15 and 0.5.16.
//
// Unknown scope therefore counts toward nothing. That under-blocks until the
// empty rows are resynced into this spelling, which is the safe direction.
func coversEveryRelease(s *Sighting) bool {
	if isSHA256Hex(strings.ToLower(strings.TrimSpace(s.Subject))) {
		return true
	}
	return strings.TrimSpace(s.Affected) == AllVersions
}

// rank orders bases by how much a single one of them is worth. Unrecognized
// values rank lowest, with Predicted, so a basis this build cannot interpret
// can never outrank one it can.
func rank(b Basis) int {
	switch b {
	case BasisReviewed:
		return 2
	case BasisHosted:
		return 1
	default: // BasisPredicted, and anything this build cannot interpret
		return 0
	}
}

// Floor is the tightest fires_at that outside claims alone justify, and whether
// they justify one at all.
//
// The scale is scan's: a false-positive budget per 100 million benign files, at
// which this artifact grades hostile, lower being worse. Turning that into
// allow or block is scan's too — this only says how far down the scale a body
// of outside evidence reaches on its own.
//
// It stops at 1 rather than 0. Zero fires at every budget including zero, which
// would rank a threat-feed citation above every verdict our own analyzer has
// ever produced; a derived level should be able to convict without outranking
// measurement.
func Floor(c Confidence) (lvl int, ok bool) {
	switch c {
	case Conclusive:
		return 1, true
	case Corroborated:
		return 10, true
	case Strong:
		return 25, true
	case Moderate:
		// Above the default budget on purpose, so a lone corpus listing does
		// not block by itself: it answers `allow` with severity `suspicious`,
		// and blocks only for a caller who has loosened past 50. A corpus takes
		// what it is sent, and one submission is a flag rather than a verdict.
		return 50, true
	case Weak:
		// The precision elbow scan measured on hopper data: at L100, 6168 bad
		// against 591 good (91%); by L250 that inverts. A single prediction is
		// worth about that much and no more.
		return 100, true
	default: // NoClaim, and any rung a newer build might add
		return 0, false
	}
}

// backed returns the confidence one rung higher, for an outside claim our own
// analysis independently supports.
//
// Not circular, and the distinction matters. parallax's Ours standing exists to
// keep our verdicts out of the corroboration LEDGER, where they would agree
// with themselves and promote their own false positives. This is the opposite
// direction: two genuinely independent lines of evidence — somebody else's
// claim and our own measurement — meeting at answer time, which is what
// corroboration actually means.
//
// Only a firing analysis backs anything. A benign verdict is our analyzer
// having looked and found nothing, which is not support; a record with no level
// is nothing at all. Neither may promote, and neither may demote either —
// disputing our own clean verdict is the triage queues' question, not a
// lookup's.
func backed(c Confidence) Confidence {
	if c == NoClaim || c >= Conclusive {
		return c
	}
	return c + 1
}

// feedTraitID is the finding id carried by a record the ledger contributed to.
//
// Namespaced apart from the analyzer's taxonomy (objectives/…, metadata/…) on
// purpose: those ids say what an artifact DOES, and this one says where a claim
// about it CAME FROM. A consumer resolving trait ids to documentation would
// otherwise look this one up and find nothing.
//
// It rides in findings[] rather than a field of its own because every caller
// already iterates findings and none has to change. That is a compatibility
// argument, not a design one, and worth saying out loud.
const feedTraitID = "intel/feed/malicious"

// ledgerTTL is how long a record standing on the ledger may be believed.
//
// Deliberately the same as recordMissTTL, and for the same reason: neither is
// invalidated by any write this process sees. Feed retractions are handled by
// removing the row, so a minute is also the whole latency of a retraction
// reaching callers, which is a cheaper mechanism than an invalidation hook that
// could not cross replication anyway.
const ledgerTTL = recordMissTTL

// feedFinding renders an assessment as the finding a caller reads.
//
// Deliberately count-shaped and names nobody. prism already declines to name
// commercial vendors in its own UI, and an API response that named them would
// republish a vendor's data under our name — a different thing from counting it.
func feedFinding(a Assessment) LookupFinding {
	crit := 5
	if a.Confidence == Weak {
		// One prediction reaches L100, which allows at any ordinary budget.
		// Reporting it as hostile would contradict the level beside it.
		crit = 4
	}
	return LookupFinding{ID: feedTraitID, Crit: crit, Desc: feedReason(a)}
}

func feedReason(a Assessment) string {
	switch {
	case len(a.Operators) > 1:
		return "Cited as malicious by " + strconv.Itoa(len(a.Operators)) +
			" independent threat intelligence sources."
	case a.Firsthand > 0:
		return "Cited as malicious by a threat intelligence source that holds or has reviewed the artifact."
	default:
		return "Cited as malicious by one threat intelligence feed."
	}
}

// tighten applies an outside floor to a measured level.
//
// -1 is the ABSENCE of a level, not the tightest one: it is the sentinel for
// "fires at no budget at all". Comparing it numerically against a floor would
// invert the whole scale and report every clean artifact we hold as the most
// hostile thing in the corpus.
//
// Outside citations may only ever make an answer stricter. A feed that has said
// nothing cannot loosen a verdict, and a feed that has spoken cannot either —
// min() in one direction, which is what makes this safe to run over every
// record rather than only over the ones nothing has analyzed.
// suspiciousCeiling mirrors scan's SUSPICIOUS_LEVEL_CEILING. Above it a level
// is not worse than benign whatever the grid, so a verdict up there is not our
// analyzer supporting anybody's claim.
const suspiciousCeiling = 3000

// fired reports whether our own analysis found something. -1 is the sentinel
// for "fires at no budget at all" and nil is no level: neither is a finding.
func fired(measured *int) bool {
	return measured != nil && *measured >= 0 && *measured <= suspiciousCeiling
}

func tighten(measured *int, floor int) int {
	if measured == nil || *measured < 0 {
		return floor
	}
	return min(*measured, floor)
}

// corroborationCounters observe whether samples.corroborated agrees with the
// ledger, as seen from the one path that holds both without extra work.
//
// Two counters, not one drift number: a missed mark and a missed clear have
// different causes and only the second implicates the ledger's DELETE arm. A
// combined figure would hide which.
//
// Observation only. samples.corroborated is a cache for predicates that cannot
// hold the subject key; this path holds it and reads the ledger directly, so
// nothing here depends on the flag being right.
type corroborationCounters struct {
	citedButNotFlagged atomic.Uint64
	flaggedButNotCited atomic.Uint64
	derived            atomic.Uint64 // records that stood on the ledger alone
	tightened          atomic.Uint64 // measured levels an outside claim tightened
}

// CorroborationStats reports what the lookup path has observed about the ledger.
type CorroborationStats struct {
	// CitedButNotFlagged is samples the ledger cites whose corroborated flag is
	// false: a mark that did not happen.
	CitedButNotFlagged uint64
	// FlaggedButNotCited is samples flagged corroborated that the ledger no
	// longer cites: a clear that did not happen.
	FlaggedButNotCited uint64
	// Derived is answers that stood on the ledger alone, for artifacts nothing
	// has analyzed.
	Derived uint64
	// Tightened is stored verdicts whose level an outside claim made stricter.
	// Worth watching on its own: it is the population where this feature
	// overrides measurement.
	Tightened uint64
}

// CorroborationStats snapshots the ledger observations.
func (db *DB) CorroborationStats() CorroborationStats {
	return CorroborationStats{
		CitedButNotFlagged: db.corroborationCounts.citedButNotFlagged.Load(),
		FlaggedButNotCited: db.corroborationCounts.flaggedButNotCited.Load(),
		Derived:            db.corroborationCounts.derived.Load(),
		Tightened:          db.corroborationCounts.tightened.Load(),
	}
}

// assess reads the ledger for an artifact's own coordinates and folds them.
//
// One or two constant-equality probes into idx_sightings_subject. Deliberately
// not gated on samples.corroborated: this path already holds the keys the ledger
// is indexed by, so the flag would save nothing and could only contribute
// staleness — and a corroboration ledger's most dangerous wrong answer is
// silence, which is indistinguishable from the truthful kind at the call site.
func (db *DB) assess(ctx context.Context, subjects ...string) Assessment {
	keys := make([]string, 0, len(subjects))
	for _, s := range subjects {
		if s != "" {
			keys = append(keys, s)
		}
	}
	if len(keys) == 0 {
		return Assessment{}
	}
	bySubject, err := db.SightingsFor(ctx, keys)
	if err != nil {
		// Best-effort, and the direction matters: failing to read the ledger
		// leaves a record exactly as the analysis produced it. An outage cannot
		// invent a conviction, only fail to add one.
		slog.WarnContext(ctx, "corroboration: ledger read failed", "subjects", len(keys), "error", err)
		return Assessment{}
	}
	// Indexed by the keys we asked for, never ranged: SightingsFor files each
	// result under the stored spelling AND every spelling that asked for it, so
	// ranging the map would count one row several times.
	var rows []Sighting
	for _, k := range keys {
		rows = append(rows, bySubject[k]...)
	}
	return Assess(rows)
}

// corroborate folds the ledger into a record built from a stored sample.
//
// Returns how long the result may be believed: zero when the ledger had nothing
// to add, so an ordinary verdict keeps the long life its analysis earns, and
// ledgerTTL once a citation is part of the answer.
func (db *DB) corroborate(ctx context.Context, r *LookupRecord, flagged bool, subjects ...string) (*LookupRecord, time.Duration) {
	a := db.assess(ctx, subjects...)
	cited := len(a.Operators) > 0
	switch {
	case cited && !flagged:
		db.corroborationCounts.citedButNotFlagged.Add(1)
	case flagged && !cited:
		db.corroborationCounts.flaggedButNotCited.Add(1)
	default:
		// They agree. Nothing to report, which is the expected case and the
		// one worth NOT counting: a metric that ticks on every lookup buries
		// the two that mean something.
	}

	confidence := a.Confidence
	// Our own analysis, when it fired, is a second and independent voice.
	// fired() is deliberately the same band scan calls suspicious-or-worse: a
	// level above that ceiling is not our analyzer backing anything up.
	if fired(r.FiresAt) {
		confidence = backed(confidence)
	}
	floor, ok := Floor(confidence)
	if !ok {
		return r, 0
	}
	if lvl := tighten(r.FiresAt, floor); r.FiresAt == nil || lvl != *r.FiresAt {
		if r.FiresAt != nil {
			db.corroborationCounts.tightened.Add(1)
		}
		r.FiresAt = &lvl
	}
	r.Findings = append(r.Findings, feedFinding(a))
	return r, ledgerTTL
}

// fromLedger builds a record for an artifact nothing has analyzed, out of what
// outside sources say about it. ErrNotFound when they say nothing.
//
// EngineVersion and AnalyzedAt stay nil, and that is the contract: an engine is
// what separates a measurement from a citation, so its absence is how every
// consumer — scan's is_verdict, beamline's cache rules, a caller's own code —
// tells the two apart.
func (db *DB) fromLedger(ctx context.Context, sha256, purl string) (*LookupRecord, time.Duration, error) {
	a := db.assess(ctx, sha256, purl)
	floor, ok := Floor(a.Confidence)
	if !ok {
		return nil, 0, ErrNotFound
	}
	r := &LookupRecord{
		Findings: []LookupFinding{feedFinding(a)},
		FiresAt:  &floor,
		// Answerable now. Analyzed selects the 202 that means "an answer is
		// coming for this key", and none is: nothing holds these bytes.
		Analyzed: true,
	}
	if sha256 != "" {
		d := sha256
		r.SHA256 = &d
	}
	if purl != "" {
		p := purl
		r.PURL = &p
	}
	reason := feedReason(a)
	r.Reason = &reason
	db.corroborationCounts.derived.Add(1)
	return r, ledgerTTL, nil
}
