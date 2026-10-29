"""Run the watcher against simulated PostgreSQL snapshots and saved history."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

WATCH = Path(__file__).resolve().parents[1] / 'watch.sh'
PSQL = r'''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
sql = args[args.index('-c')+1] if '-c' in args else (args[args.index('-tAc')+1] if '-tAc' in args else sys.stdin.read())
if 'SELECT 1' in sql: print('1')
elif "SELECT 'SUB'" in sql:
    print('SUB|replica|t|111|0|1|1|600|applytransaction|999999999999|custom_slot|' + os.environ.get('ORIGIN','100000000000') + '|17/4876E800')
    # Parallel rows must not overwrite the main worker.
    if "a.worker_type = 'apply'" not in sql:
        print('SUB|replica|t|222||1|1||DataFileRead|0|custom_slot|100000000000|17/4876E800')
    print('WORK|4|2|1|1\nTOUCH|samples|2')
elif "SELECT 'TBL'" in sql: print('TBL|samples|r|100|1000|0|0|0||||0|0|0')
elif 'SELECT subslotname' in sql: print('custom_slot')
elif "SELECT 'SLOT'" in sql:
    if os.environ.get('OFFLINE'): sys.exit(1)
    assert 'sub=custom_slot' in args, args
    gap = int(os.environ.get('GAP','1073741824'))
    print(f'SLOT|custom_slot|t|reserved|10737418240|100000000000|{100000000000+gap}')
elif "SELECT 'REM'" in sql: pass
else: raise SystemExit('Unexpected query: '+sql)
'''


class WatchTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, content in [('psql', PSQL), ('date', '#!/bin/sh\nif [ "$1" = +%s ]; then echo 1000; else echo 12:00:00; fi\n')]:
            p = self.root / name
            p.write_text(content)
            p.chmod(0o755)
        self.hist = self.root / 'hopper-replica-watch.replica.v2.hist'
        self.env = dict(os.environ, PATH=f'{self.root}:{os.environ["PATH"]}',
                        TMPDIR=str(self.root), SUBSCRIPTION='replica')

    def run_watch(self, previous_gap=2147483648, **env):
        self.hist.write_text(f'SAMP|940|1000000000|100000000000|1|600|{previous_gap}|100000000000\n')
        r = subprocess.run(['sh', str(WATCH)], env=dict(self.env, **env), text=True, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_retention_growth_is_not_falling_behind(self):
        out = self.run_watch()
        self.assertIn('confirmed gap 1.0GB', out)
        self.assertIn('retained 10.0GB', out)
        self.assertIn('catch-up', out)
        self.assertNotIn('falling-behind', out)
        self.assertIn('ETA 1m00s', out)

    def test_main_worker_parallel_workers_and_touched_tables(self):
        out = self.run_watch()
        self.assertIn('apply 111', out)
        self.assertNotIn('apply 222', out)
        self.assertIn('parallel 4: 2 IO / 1 lock / 1 idle', out)
        self.assertIn('apply txn: 2 worker(s)', out)

    def test_receiving_is_not_committing(self):
        out = self.run_watch()
        self.assertIn('unchanged over 1m00s', out)
        self.assertNotIn('/s WAL position', out)
        self.assertIn('feedback age 10m00s', out)
        self.assertNotIn('10m00s behind', out)

    def test_growing_gap_has_no_optimistic_eta(self):
        out = self.run_watch(previous_gap=0, ORIGIN='100100000000')
        self.assertIn('falling-behind', out)
        self.assertIn('ETA — (gap not shrinking)', out)
        self.assertIn('/s WAL position', out)

    def test_zero_gap_is_streaming_despite_retained_wal(self):
        out = self.run_watch(GAP='0')
        self.assertIn('confirmed gap 0B', out)
        self.assertNotIn('catch-up', out)
        self.assertNotIn('ETA', out)

    def test_missing_publisher_is_unknown(self):
        out = self.run_watch(OFFLINE='1')
        self.assertIn('gap unknown', out)
        self.assertNotIn('confirmed gap 0B', out)
        self.assertIn('||100000000000', self.hist.read_text())

    def test_origin_position_keeps_integer_precision(self):
        self.run_watch(ORIGIN='95865842747352')
        self.assertIn('|95865842747352\n', self.hist.read_text())


if __name__ == '__main__':
    unittest.main()
