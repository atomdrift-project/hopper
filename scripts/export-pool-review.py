#!/usr/bin/env python3
"""Read-only PostgreSQL evidence export; never classifies or moves samples.

Seeds are JSON lines with sha256/path/kind (see pool-review-seeds.sql).
Each output row is one content hash. JSON-valued CSV cells preserve paths and
evidence without ambiguous delimiters. Existing evidence.jsonl supports resume.
"""
import argparse
import csv
import datetime
import json
import os
from pathlib import Path
import re
import subprocess

def query(dsn, sql):
    result = subprocess.run(
        ["psql", dsn, "-X", "-q", "-w", "-At", "-v", "ON_ERROR_STOP=1"],
        input="BEGIN READ ONLY; SET LOCAL statement_timeout='120s'; SET LOCAL jit=off;\n" + sql + "\nROLLBACK;\n",
        capture_output=True, text=True,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    # splitlines() also splits literal Unicode line separators inside JSON strings.
    return [json.loads(line) for line in result.stdout.split("\n") if line.strip()]


def hashes_sql(hashes):
    if not all(re.fullmatch(r"[a-f0-9]{64}", sha) for sha in hashes):
        raise ValueError("invalid SHA256 in inventory")
    return ",".join("('" + sha + "')" for sha in hashes)


def evidence_sql(hashes):
    return """
WITH wanted(sha) AS (VALUES %s)
SELECT jsonb_build_object(
 'captured_at', now(), 'sha256', s.sha256, 'label', s.label,
 'decider', s.label_source, 'canonical_path', s.path, 'parent', s.parent,
 'skip', s.skip, 'source', s.source, 'feed', s.feed, 'size_bytes', s.size_bytes,
 'file_type', s.file_type, 'package', s.package, 'url', s.url,
 'analyzed_at', s.analyzed_at, 'updated_at', s.updated_at,
 'stored_max_crit', s.max_crit, 'stored_suspicious_count', s.suspicious_count,
 'litmus_level', s.lvl, 'litmus_class', s.litmus_class,
 'llm_result', s.llm_result,
 'cleave_file', (
   SELECT f - 'facts' FROM jsonb_array_elements(COALESCE(s.cleave_result->'files', s.cleave_result->'fs', '[]'::jsonb))
     WITH ORDINALITY AS entries(f, ord)
   WHERE lower(f->>'sha') = s.sha256 OR (ord=1 AND COALESCE(f->>'sha','')='')
   ORDER BY ord LIMIT 1),
 'locations', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'path', l.path, 'parent', l.parent_sha256, 'rel', l.rel) ORDER BY l.path)
   FROM sample_locations l WHERE l.sha256=s.sha256 AND l.parent_sha256=''), '[]'::jsonb),
 'events', COALESCE((SELECT jsonb_agg(jsonb_build_object(
   'from', e.from_label, 'to', e.to_label, 'reason', e.reason, 'at', e.observed_at)
   ORDER BY e.observed_at, e.id) FROM label_events e WHERE e.sha256=s.sha256), '[]'::jsonb)
)
FROM wanted w JOIN samples s ON s.sha256=w.sha ORDER BY s.sha256;
""" % hashes_sql(hashes)


def trait_summary(record):
    report = record.get("cleave_file")
    if report is None:
        return "unavailable", "", []
    traits = report.get("traits") or report.get("find") or report.get("ts") or []
    levels = [int(t.get("crit") or t.get("l") or 0) for t in traits]
    highest = max(levels, default=0)
    names = {0: "none", 1: "component", 2: "baseline", 3: "notable", 4: "suspicious", 5: "hostile"}
    hostile = [t.get("id") or t.get("i") or "(unnamed)" for t, level in zip(traits, levels) if level >= 5]
    return names.get(highest, str(highest)), len(hostile), hostile


def dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=os.environ.get("HOPPER_DB", ""))
    parser.add_argument("--seeds", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, help="JSONL filesystem inventory, including verified SHA256")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--render-only", action="store_true")
    parser.add_argument("--batch-size", type=int, default=50)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    if not args.render_only and not args.dsn:
        parser.error("--dsn or HOPPER_DB is required")
    args.output.mkdir(parents=True, exist_ok=True)
    seeds = [json.loads(line) for line in args.seeds.read_text().split("\n") if line.strip()]
    inventory = []
    if args.inventory:
        inventory = [json.loads(line) for line in args.inventory.read_text().split("\n") if line.strip()]
        seeds.extend(dict(r, kind="filesystem") for r in inventory if r.get("sha256"))
    wanted = {r["sha256"] for r in seeds}
    evidence_path = args.output / "evidence.jsonl"
    records = {}
    if evidence_path.exists():
        for line in evidence_path.open():
            if not line.strip():
                continue
            r = json.loads(line)
            records[r["sha256"]] = r
    if not args.render_only:
        pending = sorted(wanted - records.keys())
        with evidence_path.open("a") as out:
            for start in range(0, len(pending), args.batch_size):
                batch = pending[start:start + args.batch_size]
                found = query(args.dsn, evidence_sql(batch))
                for r in found:
                    records[r["sha256"]] = r
                    out.write(dump(r) + "\n")
                out.flush()
                if start % 1000 == 0 or start + args.batch_size >= len(pending):
                    print(f"Exported {len(records)}/{len(wanted)} hashes", flush=True)
    seed_paths = {}
    seed_kinds = {}
    verified_paths = {}
    for s in seeds:
        seed_paths.setdefault(s["sha256"], set()).add(s["path"])
        seed_kinds.setdefault(s["sha256"], set()).add(s["kind"])
    for f in inventory:
        if f.get("sha256"):
            verified_paths.setdefault(f["sha256"], set()).add(f["path"])
    fields = ["sha256", "label", "decider", "paths", "detected_level", "hostile_trait_count", "scope_kind",
              "other_pool_signals", "suggested_pool", "suggestion_reason", "decided_pool", "review_status",
              "review_rationale", "verified_collection_paths", "hostile_traits", "label_history",
              "litmus_level", "litmus_class", "canonical_path", "analyzed_at", "captured_at",
              "decision_confidence", "review_decider"]
    review_path = args.output / "review.csv"
    saved_reviews = {}
    if review_path.exists():
        csv.field_size_limit(100_000_000)
        with review_path.open(newline="") as existing:
            for row in csv.DictReader(existing):
                if row.get("decided_pool") or row.get("review_rationale"):
                    saved_reviews[row["sha256"]] = {k: row.get(k, "") for k in (
                        "decided_pool", "review_status", "review_rationale", "decision_confidence", "review_decider")}
    temporary_csv = args.output / "review.csv.tmp"
    with temporary_csv.open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        for sha in sorted(wanted):
            r = records.get(sha, {})
            locations = r.get("locations", [])
            paths = seed_paths.get(sha, set()) | {x["path"] for x in locations}
            if r.get("canonical_path"):
                paths.add(r["canonical_path"])
            # Only standalone pool roots are signals; an archive member's pool
            # describes the containing archive, not necessarily this content.
            signals = {x["path"].split("/", 1)[0] for x in locations if not x["parent"] and "!!" not in x["path"]}
            signals &= {"good", "bad", "dual-use"}
            if r.get("label") in {"good", "bad", "dual-use"}:
                signals.add(r["label"])
            suggestion = next(iter(signals)) if len(signals) == 1 else "inconclusive"
            reason = ("Other label/pool is a review signal; verify evidence and physical presence."
                      if len(signals) == 1 else "Conflicting pool signals; individual review required."
                      if signals else "No alternative pool signal; inconclusive is the review default.")
            level, count, hostile = trait_summary(r)
            row = dict(
                sha256=sha, label=r.get("label", ""), decider=r.get("decider", ""), paths=dump(sorted(paths)),
                detected_level=level, hostile_trait_count=count,
                scope_kind="standalone" if seed_kinds[sha] & {"standalone", "filesystem"}
                else "reviewed_label" if "label" in seed_kinds[sha] else "archive_member",
                other_pool_signals=dump(sorted(signals)),
                suggested_pool=suggestion, suggestion_reason=reason, decided_pool="", review_status="pending",
                review_rationale="", verified_collection_paths=dump(sorted(verified_paths.get(sha, set()))),
                hostile_traits=dump(hostile), label_history=dump(r.get("events", [])),
                litmus_level=r.get("litmus_level", ""), litmus_class=r.get("litmus_class", ""),
                canonical_path=r.get("canonical_path", ""), analyzed_at=r.get("analyzed_at", ""),
                captured_at=r.get("captured_at", ""))
            row.update(saved_reviews.get(sha, {}))
            writer.writerow(row)
    temporary_csv.replace(review_path)
    manifest = dict(generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    sha256_count=len(wanted), database_records=len(wanted & records.keys()),
                    missing_database_records=sorted(wanted - records.keys()),
                    scope="Reviewed labels plus legacy/current reviewed paths, indexed archive descendants, and filesystem inventory.",
                    paths="All standalone locations, reviewed-pool archive locations, and canonical paths; unrelated virtual aliases omitted.",
                    consistency="Read-only snapshot per batch; revalidate before applying decisions.",
                    decisions="Suggestions are not decisions; preserved individual review fields: " + str(len(saved_reviews)),
                    live_mutations=False)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(dump(manifest))


if __name__ == "__main__":
    main()
