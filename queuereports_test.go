package hopper

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Every queue must anti-join a report named for itself, on BOTH its selector and
// its depth. That guard used to be a per-queue option and grew three spellings:
// a literal NOT EXISTS in the SQL, an ExcludeReportType passed by hand, and --
// for six of them -- nothing at all, which re-offered judged work forever.
//
// This reads the registry rather than a hand-written list, so a queue added
// without the guard fails here instead of quietly rotating samples in
// production. It also catches the subtler mistake of stamping the wrong name,
// which would park a sample against another queue's marker.
func TestEveryQueueExcludesItsOwnReport(t *testing.T) {
	for name, q := range TriageQueues {
		got := queueFilter(name, TriageFilter{})
		if got.ExcludeReportType != name {
			t.Errorf("%s: queueFilter stamps %q, want the queue's own name",
				name, got.ExcludeReportType)
		}
		if q.Name != name {
			t.Errorf("registry key %q holds a queue named %q; the report type is derived "+
				"from the key, so the two must agree", name, q.Name)
		}
	}
}

// queueFilter must not quietly discard the ordering or filters a caller set --
// it adds the report guard, it does not replace the filter.
func TestQueueFilterPreservesTheCallersFilter(t *testing.T) {
	got := queueFilter("bad", TriageFilter{Order: TriageRepair, Ecosystem: "npm"})
	if got.Order != TriageRepair || got.Ecosystem != "npm" {
		t.Errorf("queueFilter dropped caller fields: %+v", got)
	}
	if got.ExcludeReportType != "bad" {
		t.Errorf("ExcludeReportType = %q, want bad", got.ExcludeReportType)
	}
	// staleTriageFilter is the same rule with an ordering; it must still stamp.
	if s := staleTriageFilter("popular"); s.ExcludeReportType != "popular" || s.Order != TriageStale {
		t.Errorf("staleTriageFilter(popular) = %+v", s)
	}
}

// The registry's own text must not carry a bare TriageFilter{} for a queue --
// that is the shape the six missing guards had. Source-level because the closure
// bodies are not reachable from a test without a database.
func TestRegistryUsesQueueFilterEverywhere(t *testing.T) {
	b, err := readSourceFile("triagequeues.go")
	if err != nil {
		t.Skipf("source not readable: %v", err)
	}
	for i, line := range strings.Split(b, "\n") {
		if !strings.Contains(line, "TriageFilter{}") {
			continue
		}
		if !strings.Contains(line, "queueFilter(") {
			t.Errorf("triagequeues.go:%d passes a bare TriageFilter{}; route it through "+
				"queueFilter so the queue keeps its report guard:\n\t%s",
				i+1, strings.TrimSpace(line))
		}
	}
}

func readSourceFile(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}

// Re-entry after a report needs BOTH a re-analysis and ReportCooldown to elapse.
// Each half alone is too weak: a same-day rescan re-admits work judged hours
// ago, and age alone re-admits work nothing has re-examined. The four cases
// below are the truth table.
func TestReportCooldownRequiresRescanAndAge(t *testing.T) {
	ctx := t.Context()
	db := openTestDB(t)

	old := time.Now().Add(-10 * 24 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)

	// analyzedAt is when the sample was last scanned; reportAt when it was judged.
	seed := func(n int, analyzedAt, reportAt time.Time) string {
		sha := staleTestSHA(n)
		mustInsert(t, ctx, db, &Sample{
			SHA256: sha, Source: "test", Label: "bad", LabelSource: "test",
			Path: "bad/" + sha, FileType: "elf",
			CleaveResult: []byte(`{"files":[]}`),
		})
		if _, err := db.lite.ExecContext(ctx,
			`UPDATE samples SET analyzed_at = ? WHERE sha256 = ?`, analyzedAt, sha); err != nil {
			t.Fatalf("stamp analyzed_at: %v", err)
		}
		if _, err := db.lite.ExecContext(ctx,
			`INSERT INTO reports (sha256, report_type, content, created_at) VALUES (?, 'bad', '{}', ?)`,
			sha, reportAt); err != nil {
			t.Fatalf("insert report: %v", err)
		}
		return sha
	}

	// rescanned after an OLD report -> eligible again
	eligible := seed(61, time.Now().Add(-2*time.Hour), old)
	// rescanned, but the report is younger than the cooldown -> still parked
	tooRecent := seed(62, time.Now().Add(-2*time.Hour), recent)
	// old report, but never re-analyzed since -> still parked
	notRescanned := seed(63, old.Add(-24*time.Hour), old)

	clause, args := triageFilterClauseSQLite(queueFilter("bad", TriageFilter{}), "samples")
	rows, err := db.lite.QueryContext(ctx,
		`SELECT sha256 FROM samples WHERE label = 'bad'`+clause, args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close() //nolint:errcheck // test
	got := map[string]bool{}
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			t.Fatal(err)
		}
		got[sha] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if !got[eligible] {
		t.Error("a sample rescanned after a report older than ReportCooldown must be eligible again")
	}
	if got[tooRecent] {
		t.Error("a report younger than ReportCooldown must still park, even after a rescan")
	}
	if got[notRescanned] {
		t.Error("age alone must not re-admit; the sample has not been re-analyzed since the report")
	}
}
