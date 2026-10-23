"""Exercise the actual healer with simulated PostgreSQL failures and progress."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HEALER = Path(__file__).resolve().parents[1] / "replica-heal.sh"
PSQL = r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
args = sys.argv[1:]
sql = args[args.index('-tAc') + 1] if '-tAc' in args else (
    args[args.index('-c') + 1] if '-c' in args else sys.stdin.read())
if '-h' in args:
    if os.environ.get('OFFLINE'): sys.exit(1)
    if 'confirmed_flush_lsn' in sql: print('100')
    elif 'pg_constraint' not in sql: print('public.samples|id|ALTER TABLE public.samples ADD COLUMN id integer|')
elif 'ALTER SUBSCRIPTION' in sql:
    with open(os.environ['CALLS'], 'a') as f: f.write(sql + '\n')
    sys.exit(1 if os.environ.get('ENABLE_FAIL') else 0)
elif 'subenabled' in sql: print(os.environ.get('ENABLED', 'f'))
elif 'pg_replication_origin_status' in sql: print(os.environ.get('POSITION', '42:1/100'))
elif 'pg_class' in sql:
    if "a.attgenerated = 's'" not in sql: print('public.samples|id')
elif 'SELECT 1' in sql: print('1')
else: raise SystemExit('Unexpected SQL: ' + sql)
'''


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.calls = self.root / 'calls'
        self.retry = self.state / 'retry-test_replica'
        for name, content in [('psql', PSQL), ('date', '#!/bin/sh\nif [ "$1" = +%s ]; then echo "$TEST_NOW"; else echo test-time; fi\n')]:
            path = self.root / name
            path.write_text(content)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{self.root}:{os.environ["PATH"]}',
                        HEAL_STATE_DIR=str(self.state), SUBSCRIPTION='test_replica',
                        REPLICA_MATCH_RELOPTIONS='false', CALLS=str(self.calls))

    def run_healer(self, now=1000, **env):
        return subprocess.run(['sh', str(HEALER)], env=dict(self.env, TEST_NOW=str(now), **env),
                              capture_output=True, text=True)

    def attempts(self):
        return len(self.calls.read_text().splitlines()) if self.calls.exists() else 0

    def test_transient_failure_reenabled(self):
        result = self.run_healer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.attempts(), 1)
        self.assertEqual(self.retry.read_text().strip(), '42:1/100 60 1060')

    def test_persistent_failure_backs_off_and_caps(self):
        now = 1000
        for attempts, delay in enumerate([60, 120, 240, 480, 900, 900], 1):
            self.assertEqual(self.run_healer(now).returncode, 0)
            self.assertEqual(self.attempts(), attempts)
            self.assertEqual(self.run_healer(now + 1).returncode, 1)
            self.assertEqual(self.attempts(), attempts)
            self.assertEqual(int(self.retry.read_text().split()[1]), delay)
            now += delay

    def test_committed_progress_resets_backoff(self):
        self.run_healer()
        result = self.run_healer(1001, POSITION='42:1/200')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.attempts(), 2)
        self.assertEqual(self.retry.read_text().strip(), '42:1/200 60 1061')

    def test_maintenance_and_unreachable_publisher_leave_disabled(self):
        (self.state / 'maintenance').touch()
        self.assertEqual(self.run_healer().returncode, 0)
        (self.state / 'maintenance').unlink()
        self.assertEqual(self.run_healer(OFFLINE='1').returncode, 1)
        self.assertEqual(self.attempts(), 0)

    def test_enabled_lagging_subscription_is_not_restarted(self):
        result = self.run_healer(ENABLED='t')
        self.assertEqual(result.returncode, 1)
        self.assertIn('behind the publisher', result.stderr)
        self.assertEqual(self.attempts(), 0)

    def test_failed_enable_also_backs_off(self):
        self.assertEqual(self.run_healer(ENABLE_FAIL='1').returncode, 1)
        self.assertEqual(self.run_healer(1001, ENABLE_FAIL='1').returncode, 1)
        self.assertEqual(self.attempts(), 1)


if __name__ == '__main__':
    unittest.main()
