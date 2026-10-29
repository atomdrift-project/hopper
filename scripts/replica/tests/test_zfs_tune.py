"""Ensure replica setup preserves deliberate pool maintenance settings."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'zfs-tune.sh'


class AutotrimTest(unittest.TestCase):
    def run_tune(self, mode='apply', choice=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            calls = root / 'calls'
            for name, body in {
                'id': 'echo 0',
                'zfs': 'echo "zfs $*" >> "$CALLS"',
                'zpool': 'echo "zpool $*" >> "$CALLS"; if [ "$1" = get ]; then echo on; fi',
            }.items():
                path = root / name
                path.write_text('#!/bin/sh\n' + body + '\n')
                path.chmod(0o755)
            env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', CALLS=str(calls))
            env.pop('REPLICA_ZFS_AUTOTRIM', None)
            if choice is not None:
                env['REPLICA_ZFS_AUTOTRIM'] = choice
            result = subprocess.run(['sh', str(SCRIPT), mode, 'tank/pgdata'],
                                    env=env, text=True, capture_output=True)
            return result, calls.read_text() if calls.exists() else ''

    def test_default_preserves_pool_policy(self):
        result, calls = self.run_tune()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zfs set sync=disabled tank/pgdata', calls)
        self.assertNotIn('zpool', calls)

    def test_explicit_override(self):
        result, calls = self.run_tune(choice='off')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zpool set autotrim=off tank', calls)

    def test_matching_setting_is_not_reapplied(self):
        result, calls = self.run_tune(choice='on')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('zpool set', calls)

    def test_promotion_does_not_override_trim_policy(self):
        result, calls = self.run_tune(mode='revert', choice='off')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zfs set sync=standard tank/pgdata', calls)
        self.assertNotIn('zpool', calls)

    def test_invalid_option_fails_before_mutations(self):
        result, calls = self.run_tune(choice='invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, '')


if __name__ == '__main__':
    unittest.main()
