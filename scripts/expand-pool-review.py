#!/usr/bin/env python3
"""Add reviewed-pool archive descendants to JSONL seeds, using parent indexes."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("export_pool_review", Path(__file__).with_name("export-pool-review.py"))
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True)
    parser.add_argument("--seeds", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() == args.seeds.resolve():
        parser.error("output must differ from input")
    rows = [json.loads(x) for x in args.seeds.read_text().split("\n") if x.strip()]
    known = {(r["sha256"], r["path"]) for r in rows}
    pending = {r["sha256"] for r in rows}
    visited = set()
    with args.output.open("w") as out:
        for row in rows:
            out.write(export.dump(row) + "\n")
        while pending:
            batch = sorted(pending)[:100]
            sql = """
WITH parents(sha) AS (VALUES %s)
SELECT json_build_object('sha256', l.sha256, 'path', l.path, 'kind', 'member')
FROM parents p CROSS JOIN LATERAL (
 SELECT sha256, path FROM sample_locations WHERE parent_sha256=p.sha AND parent_sha256<>''
 AND rel IN ('', 'unpacked')
 AND (path LIKE 'purgatory/%%' OR path LIKE 'inconclusive/%%' OR path LIKE 'dual-use/%%')
 OFFSET 0
) l;
""" % export.hashes_sql(batch)
            found = export.query(args.dsn, sql)
            visited.update(batch)
            pending.difference_update(batch)
            for row in found:
                key = (row["sha256"], row["path"])
                if key not in known:
                    known.add(key)
                    out.write(export.dump(row) + "\n")
                if row["sha256"] not in visited:
                    pending.add(row["sha256"])
            out.flush()
            if len(visited) % 5000 == 0 or not pending:
                print(f"Expanded {len(visited)} hashes; {len(pending)} remaining; {len(known)} paths", flush=True)


if __name__ == "__main__":
    main()
