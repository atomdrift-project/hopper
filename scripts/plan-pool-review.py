#!/usr/bin/env python3
"""Create local review views and a consolidation preview; performs no moves."""
import argparse
import collections
import csv
import datetime
import json
from pathlib import Path, PurePosixPath


def safe_path(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe relative path: {value!r}")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    csv.field_size_limit(100_000_000)
    root = args.directory
    decisions = {}
    counts = {key: collections.Counter() for key in ("scope_kind", "label", "suggested_pool", "review_status", "decided_pool")}
    with (root / "review.csv").open(newline="") as source, (root / "standalone-review.csv").open("w", newline="") as subset:
        reader = csv.DictReader(source)
        writer = csv.DictWriter(subset, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            for key, counter in counts.items():
                counter[row[key]] += 1
            if row["scope_kind"] == "standalone":
                writer.writerow(row)
            if row["review_status"] in {"reviewed", "best_guess"} and row["decided_pool"]:
                if row["decided_pool"] not in {"good", "bad", "inconclusive", "dual-use"} or not row["review_rationale"].strip():
                    raise ValueError("Invalid decision for " + row["sha256"])
                if row["sha256"] in decisions:
                    raise ValueError("Duplicate reviewed SHA256")
                decisions[row["sha256"]] = row
    emitted = set()
    with (root / "evidence.jsonl").open() as evidence, (root / "consolidation-preview.jsonl").open("w") as out:
        for line in evidence:
            record = json.loads(line)
            sha = record["sha256"]
            if sha not in decisions:
                continue
            if sha in emitted:
                raise ValueError("Duplicate evidence for " + sha)
            emitted.add(sha)
            row = decisions[sha]
            pool = row["decided_pool"]
            physical = {safe_path(l["path"]) for l in record["locations"] if not l["parent"] and "!!" not in l["path"]}
            physical.update(safe_path(p) for p in json.loads(row["verified_collection_paths"]))
            candidates = sorted(p for p in physical if p.startswith(pool + "/"))
            canonical = record.get("canonical_path", "")
            if canonical in candidates:
                destination = canonical
            elif candidates:
                destination = candidates[0]
            else:
                basename = PurePosixPath(canonical).name if canonical and "!!" not in canonical else sha
                destination = f"{pool}/reviewed/{sha}/{basename}"
            plan = dict(sha256=sha, decided_pool=pool, rationale=row["review_rationale"],
                        review_status=row["review_status"], scope_kind=row["scope_kind"],
                        catalog_label_at_capture=record["label"], catalog_updated_at=record["updated_at"],
                        candidate_destination=safe_path(destination) if physical else None, candidate_standalone_paths=sorted(physical),
                        virtual_paths_to_preserve=[p for p in json.loads(row["paths"]) if "!!" in p],
                        state="preview_requires_live_verification", applied=False,
                        preconditions=["Pause movers and discard/rebuild stale walk staging.",
                                       "Re-read label, decision history, and all current locations; abort if changed.",
                                       "Map renamed roots; hash each existing source and destination; never overwrite different bytes.",
                                       "Preserve sidecars and provenance; journal changes and verify durable destination before retiring duplicates.",
                                       "Retain containment edges and repair virtual aliases when their containing archive moves.",
                                       "Retire proven ghost aliases with audit history; do not mark the whole sample missing."])
            out.write(json.dumps(plan, ensure_ascii=False) + "\n")
    if decisions.keys() - emitted:
        raise ValueError("Missing evidence for reviewed hashes")
    summary = dict(generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   rows=sum(counts["label"].values()), counts=counts, planned_hashes=len(emitted), applied=False)
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
