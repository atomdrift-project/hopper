package main

// mv relabels samples by SHA-256.
//
// post-triage is the batch form of this: it walks the directories an
// /xtriage-* run sorted, hashes every file, and flips them all. That works
// when the triage output *is* a directory of files. It does not help when the
// answer to a triage run is a list — "these nine of the forty are actually
// hostile" — because the operator would have to copy those bytes into a
// scratch directory purely so a walker could hash them back into the SHA-256s
// they already had.
//
// So this takes the identifiers directly and sends the same request to the
// same endpoint. The master does the work: POST /api/triage moves the on-disk
// artifact into its corrected pool bucket and flips the DB label in one
// operation, which is why "mv" is the honest name — a relabel here is a move,
// and a move is a relabel. Nothing is copied over the wire.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// mvTargets maps the -target value to the field of triageVerdict that carries
// it. The two flows differ in where the sample lands, not just in spelling:
//
//   - verdict ("good"/"bad") is the operator correction — the file moves to
//     <target>/mislabeled-<old-label>/<basename> so the bucket records what it
//     was rescued from, and the label flips with source "triage".
//   - ruling ("sighted"/"pending"/"review") is the classification flow — the
//     file moves into that pool's tree with its source subpath preserved.
//     "pending" and "review" are path-only workflow moves and the master
//     rejects them for anything not currently labeled "unknown".
//
// Correcting a mislabeled sample is the first flow, which is why -target=good
// and -target=bad send a verdict rather than the identically-spelled ruling.
var mvTargets = map[string]string{
	"good":    "verdict",
	"bad":     "verdict",
	"sighted": "ruling",
	"pending": "ruling",
	"review":  "ruling",
}

func mvTargetNames() string {
	return "good, bad, sighted, pending, review"
}

func cmdMv(ctx context.Context) error {
	f := flag.NewFlagSet("mv", flag.ExitOnError)
	baseURL := f.String("url", "http://hopper-api:8081/", "hopper master API base URL") //nolint:revive // unsecure-url-scheme: internal cluster HTTP
	target := f.String("target", "", "corrected label: "+mvTargetNames())
	source := f.String("source", "", "override the recorded label_source (default: triage/promoter)")
	dryRun := f.Bool("dry-run", false, "ask the master to report the planned moves without touching anything")
	parseFlags(f, os.Args[2:])

	kind, ok := mvTargets[strings.ToLower(strings.TrimSpace(*target))]
	if !ok {
		if *target == "" {
			return errors.New("mv: -target is required (" + mvTargetNames() + ")")
		}
		return fmt.Errorf("mv: unknown -target %q (want one of: %s)", *target, mvTargetNames())
	}
	label := strings.ToLower(strings.TrimSpace(*target))

	shas, err := collectMvSHAs(f.Args(), os.Stdin)
	if err != nil {
		return err
	}
	if len(shas) == 0 {
		return errors.New("mv: no SHA-256 arguments (pass them on the command line, or `-` to read stdin)")
	}

	verdicts := make([]triageVerdict, 0, len(shas))
	for _, sha := range shas {
		v := triageVerdict{SHA256: sha, Source: *source}
		if kind == "verdict" {
			v.Verdict = label
		} else {
			v.Ruling = label
		}
		verdicts = append(verdicts, v)
	}

	writeStdoutf("relabeling %d sample(s) to %s\n", len(verdicts), label)

	// The master caps one request at maxTriageVerdicts, so a larger list is
	// sent in order as several requests rather than refused.
	var moved, noop, absent, failed int
	for batch := range chunkVerdicts(verdicts, maxTriageVerdicts) {
		resp, err := postTriage(ctx, *baseURL, triageRequest{Verdicts: batch, DryRun: *dryRun})
		if err != nil {
			return err
		}
		for _, r := range resp.Results {
			if r.Status == "moved" || r.Status == "plan" {
				writeStdoutf("  %-9s %s  %s -> %s\n", r.Status, r.SHA256, r.OldPath, r.NewPath)
			} else {
				writeStdoutf("  %-9s %s  %s\n", r.Status, r.SHA256, r.Error)
			}
		}
		moved += resp.Moved
		noop += resp.Noop
		absent += resp.Absent
		failed += resp.Failed
	}

	verb := "moved"
	if *dryRun {
		verb = "planned"
	}
	writeStdoutf("\nSummary: %d %s, %d noop, %d absent, %d failed\n", moved, verb, noop, absent, failed)
	if failed > 0 {
		return fmt.Errorf("mv: %d sample(s) failed", failed)
	}
	return nil
}

// collectMvSHAs normalizes the positional arguments into lowercase SHA-256s,
// preserving order and dropping repeats.
//
// A bare "-" argument, or no argument at all, reads the list from stdin
// instead, one identifier per whitespace-separated field. That is the shape
// triage output already has — a report or a `jq -r` over a scan — so feeding
// it in needs no intermediate file.
func collectMvSHAs(args []string, stdin io.Reader) ([]string, error) {
	fields := args
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		var err error
		if fields, err = readSHAFields(stdin); err != nil {
			return nil, fmt.Errorf("mv: read stdin: %w", err)
		}
	}

	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, raw := range fields {
		sha := strings.ToLower(strings.TrimSpace(raw))
		if sha == "" {
			continue
		}
		if !validSHA256(sha) {
			return nil, fmt.Errorf("mv: %q is not a SHA-256", raw)
		}
		if _, dup := seen[sha]; dup {
			continue
		}
		seen[sha] = struct{}{}
		out = append(out, sha)
	}
	return out, nil
}

// readSHAFields splits stdin on whitespace so both a one-per-line list and a
// single wrapped line work.
func readSHAFields(r io.Reader) ([]string, error) {
	var out []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		out = append(out, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// chunkVerdicts yields consecutive slices of at most size elements.
func chunkVerdicts(verdicts []triageVerdict, size int) func(func([]triageVerdict) bool) {
	return func(yield func([]triageVerdict) bool) {
		for start := 0; start < len(verdicts); start += size {
			end := min(start+size, len(verdicts))
			if !yield(verdicts[start:end]) {
				return
			}
		}
	}
}
