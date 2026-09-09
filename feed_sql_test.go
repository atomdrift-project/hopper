package hopper

import (
	"strings"
	"testing"
	"time"
)

// flattened collapses every run of whitespace to one space, so the pinned
// query text below asserts the SQL's SHAPE and not its line breaks. The traps
// these tests exist to catch are semantic — a predicate dropped, EXISTS or
// DISTINCT reintroduced — and none of them can hide in a re-wrap.
func flattened(sql string) string {
	return strings.Join(strings.Fields(sql), " ")
}

// The feed dropdown queries are loose index scans whose shape matters more
// than usual: two planner traps (partial-index proof with parameters, and
// EXISTS flattening) turn a ~2k-buffer query back into a full scan of the
// replica. Pin the text so a well-meaning cleanup cannot reintroduce them.
// See feedEcosystemsSQL for the measurements.
func TestFeedEcosystemsSQL(t *testing.T) {
	since := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	sql, args := feedEcosystemsSQL("", "", &since)
	if len(args) != 1 || args[0] != since {
		t.Fatalf("args = %v, want [since]", args)
	}
	for _, want := range []string{
		"s.ecosystem > eco.ecosystem AND s.ecosystem <> ''",
		"LATERAL (SELECT 1 FROM samples s WHERE s.ecosystem = e.ecosystem AND s.ecosystem <> '' AND s.parent = '' AND s.cleave_result IS NOT NULL AND s.litmus_result IS NOT NULL AND s.created_at >= $1 LIMIT 1) hit",
		"ORDER BY e.ecosystem",
	} {
		if !strings.Contains(flattened(sql), want) {
			t.Errorf("SQL missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "EXISTS") || strings.Contains(sql, "DISTINCT") {
		t.Errorf("SQL must not use EXISTS or DISTINCT (both re-scan the window):\n%s", sql)
	}

	// Filtered calls deliberately keep the original DISTINCT query: the probe
	// form is no faster once the planner has to filter source/label on the heap.
	sql, args = feedEcosystemsSQL("forager", "bad", nil)
	if len(args) != 3 || args[0] != "forager" || args[1] != "bad" || args[2] != (*time.Time)(nil) {
		t.Fatalf("args = %v, want [forager bad <nil>]", args)
	}
	if !strings.Contains(sql, "SELECT DISTINCT ecosystem FROM samples") || strings.Contains(sql, "RECURSIVE") {
		t.Errorf("filtered SQL must be the legacy form:\n%s", sql)
	}

	sql, args = feedEcosystemsSQL("", "", nil)
	if len(args) != 0 || strings.Contains(sql, "created_at") {
		t.Errorf("zero since must not add a window (args=%v):\n%s", args, sql)
	}
	t.Logf("prism form:\n%s", func() string { s, _ := feedEcosystemsSQL("", "", &since); return s }())
}

func TestFeedDomainsSQL(t *testing.T) {
	sql, args := feedDomainsSQL("", "")
	if args != nil {
		t.Fatalf("args = %v, want nil", args)
	}
	if !strings.Contains(sql, "s.domain > dom.domain AND s.domain <> ''") ||
		!strings.HasSuffix(sql, "SELECT domain FROM dom WHERE domain IS NOT NULL ORDER BY domain") {
		t.Errorf("unfiltered SQL wrong:\n%s", sql)
	}
	if strings.Contains(sql, "LATERAL") {
		t.Errorf("unfiltered form needs no probe:\n%s", sql)
	}
	t.Logf("unfiltered form:\n%s", sql)

	sql, args = feedDomainsSQL("forager", "")
	if len(args) != 2 || args[0] != "forager" || args[1] != "" {
		t.Fatalf("args = %v, want [forager \"\"]", args)
	}
	if !strings.Contains(sql, "SELECT DISTINCT domain FROM samples") || strings.Contains(sql, "RECURSIVE") {
		t.Errorf("filtered SQL must be the legacy form:\n%s", sql)
	}
	t.Logf("filtered form:\n%s", sql)
}
