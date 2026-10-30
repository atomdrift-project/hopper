#!/usr/bin/env python3
"""Hash regular sample files in reviewed pools; write JSONL to stdout, read only."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    for pool in ("purgatory", "inconclusive", "dual-use"):
        root = args.root / pool
        if not root.exists():
            print(json.dumps({"pool": pool, "absent": True}), flush=True)
            continue
        for directory, _, names in os.walk(root, followlinks=False):
            for name in sorted(names):
                path = Path(directory) / name
                result = {"path": str(path.relative_to(args.root)), "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
                try:
                    before = path.lstat()
                    result.update(size=before.st_size, mtime_ns=before.st_mtime_ns)
                    if not stat.S_ISREG(before.st_mode):
                        result["error"] = "not a regular file"
                    elif name.endswith(".forage.json"):
                        result["sidecar"] = True
                    else:
                        digest = hashlib.sha256()
                        with path.open("rb") as source:
                            while block := source.read(1024 * 1024):
                                digest.update(block)
                        after = path.lstat()
                        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                            result["error"] = "file changed during hashing"
                        else:
                            result["sha256"] = digest.hexdigest()
                except OSError as error:
                    result["error"] = str(error)
                print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
