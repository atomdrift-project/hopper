package main

import (
	"fmt"
	"maps"
	"net/url"
	"testing"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// queueFiles queues n files on disk at priority p, named prefix0 to
// prefix(n-1) in the order hopper saw them, and queued in that order.
func queueFiles(t *testing.T, pool *pgxpool.Pool, p store.Priority, prefix string, n int) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `WITH s AS (
			INSERT INTO samples (sha256, size_bytes, file_type)
			SELECT sha256(convert_to($1 || i, 'UTF8')), 900, 'npm' FROM generate_series(0, $2 - 1) i
			ORDER BY i RETURNING id),
		l AS (INSERT INTO locations (path, sample_id) SELECT 'pool/' || id, id FROM s)
		INSERT INTO queue (sample_id, priority, queued_at)
		SELECT id, $3, now() - make_interval(secs => 1000000 - id) FROM s`, prefix, n, int16(p)); err != nil {
		t.Fatal(err)
	}
}

// tiers returns the names of the files handed out, by tier, in the order
// they were handed out, and fails the test on a file handed out twice.
func tiers(t *testing.T, jobs []hopper.ClaimJob, names map[string]string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	seen := map[string]bool{}
	for _, j := range jobs {
		if seen[j.SHA256] {
			t.Errorf("%s handed out twice in one batch", names[j.SHA256])
		}
		seen[j.SHA256] = true
		out[j.Tier] = append(out[j.Tier], names[j.SHA256])
	}
	return out
}

// queuedNames maps the digests queueFiles made back to their names.
func queuedNames(prefix string, n int) map[string]string {
	out := make(map[string]string, n)
	for i := range n {
		name := fmt.Sprintf("%s%d", prefix, i)
		out[hexSum([]byte(name))] = name
	}
	return out
}

// handOut claims count jobs for a worker with 8 slots.
func handOut(t *testing.T, api *apiServer, count int, llm bool) []hopper.ClaimJob {
	t.Helper()
	jobs, err := api.claimJobs(t.Context(), "w1", count, nil, 0, 8, llm)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

// The unanalyzed backlog is served from both ends, half each, no file twice;
// first scans of compromised packages take at most their share, newest first.
func TestQueueLadderShares(t *testing.T) {
	api, _, pool := verdictAPI(t)
	queueFiles(t, pool, store.QueueCompromised, "c", 20)
	queueFiles(t, pool, store.QueueNew, "n", 20)
	names := queuedNames("c", 20)
	maps.Copy(names, queuedNames("n", 20))
	got := tiers(t, handOut(t, api, 8, true), names)
	want := map[string][]string{
		tierCompromised:      {"c19", "c18"}, // 8 × compromisedShare
		tierUnanalyzedNewest: {"n19", "n18", "n17"},
		tierUnanalyzed:       {"n0", "n1", "n2"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("batch %v, want %v", got, want)
	}
}

// With fewer files than the batch, the two ends meet and hand out each file
// once.
func TestQueueLadderBothEndsMeet(t *testing.T) {
	api, _, pool := verdictAPI(t)
	queueFiles(t, pool, store.QueueNew, "n", 3)
	jobs := handOut(t, api, 8, true)
	got := tiers(t, jobs, queuedNames("n", 3))
	if len(jobs) != 3 || fmt.Sprint(got) != fmt.Sprint(map[string][]string{tierUnanalyzedNewest: {"n2", "n1", "n0"}}) {
		t.Errorf("batch %v, want all three from the newest end", got)
	}
}

// Files to describe go only to a worker that has not said it lacks an LLM,
// and at most their share of the batch.
func TestQueueLadderDescribeGate(t *testing.T) {
	api, _, pool := verdictAPI(t)
	queueFiles(t, pool, store.QueueDescribe, "d", 20)
	queueFiles(t, pool, store.QueueNew, "n", 20)
	names := queuedNames("d", 20)
	maps.Copy(names, queuedNames("n", 20))
	if got := tiers(t, handOut(t, api, 10, false), names); len(got[tierMissingLLM]) != 0 {
		t.Errorf("a worker without an LLM was handed files to describe: %v", got)
	}
	if got := tiers(t, handOut(t, api, 10, true), names); len(got[tierMissingLLM]) != 1 { // 10 × describeShare
		t.Errorf("batch %v, want one file to describe", got)
	}

	for form, want := range map[string]bool{"": true, "llm=1": true, "llm=0": false} {
		q, err := url.ParseQuery(form)
		if err != nil {
			t.Fatal(err)
		}
		if got := parseNextParams(q).llm; got != want {
			t.Errorf("parseNextParams(%q).llm = %v, want %v", form, got, want)
		}
	}
}
