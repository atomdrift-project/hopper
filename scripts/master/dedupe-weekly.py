#!/usr/bin/env python3
"""Run a weekly modifying dedupe pass, preserving logs and preventing overlap."""

import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def previous_sweep_running(pid_file):
    if pid_file is None or not pid_file.exists():
        return False
    # The initial ad-hoc runner wrote a literal backslash-n after its PID.
    pid = int(pid_file.read_text().replace("\\n", "").strip())
    if pid <= 1:
        raise ValueError(f"invalid sweep PID in {pid_file}")
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        # A foreign-user PID is a reused PID, not our original sweep.
        return False
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        # The process may have exited between kill(0) and ps.
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        raise RuntimeError(f"cannot inspect previous sweep PID {pid}")
    return "dedupe-locations" in result.stdout


def write_status(path, status):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(status, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--data", default="/data/samples", type=Path)
    parser.add_argument("--state-dir", type=Path,
                        default=Path.home() / ".local/state/hopper")
    parser.add_argument("--initial-pid-file", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="check configuration and overlap without running dedupe")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    data = args.data.resolve(strict=True)
    if not os.access(binary, os.X_OK) or not data.is_dir():
        raise ValueError("binary must be executable and data must be a directory")
    state = args.state_dir.resolve()
    state.mkdir(parents=True, exist_ok=True)
    with (state / "weekly-dedupe.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"{stamp()} skipped: weekly dedupe is already running", flush=True)
            return 0
        pid_file = state / "weekly-dedupe.pid"
        for previous in (args.initial_pid_file, pid_file):
            if previous_sweep_running(previous):
                print(f"{stamp()} skipped: dedupe from {previous} is still running", flush=True)
                return 0
        command = [str(binary), "dedupe-locations", "--data", str(data),
                   "--consolidate", "--verify=false", "--batch", "100"]
        if args.check:
            print(f"{stamp()} ready: {command}", flush=True)
            return 0
        suffix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        output = state / f"dedupe-weekly-{suffix}.out"
        status_file = state / "weekly-dedupe.json"
        with output.open("x") as log:
            # Let the child retain the lock if this wrapper is interrupted.
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, pass_fds=(lock.fileno(),))
            pid_file.write_text(str(child.pid) + "\n")
            status = {"started_at": stamp(), "pid": child.pid,
                      "command": command, "output": str(output)}
            write_status(status_file, status)
            print(f"{stamp()} started PID {child.pid}; output: {output}", flush=True)
            code = child.wait()
            status.update(finished_at=stamp(), exit_code=code)
            write_status(status_file, status)
            print(f"{stamp()} finished with exit status {code}; output: {output}", flush=True)
            return code


if __name__ == "__main__":
    raise SystemExit(main())
