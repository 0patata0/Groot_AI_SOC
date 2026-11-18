"""Exercise the real preflight allowlist; never reach ownership/host checks."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]

class RemoteActions(unittest.TestCase):
    def test_clock_gate_precedes_every_dispatch_without_export_stdout(self):
        source=(ROOT/'deployment/remote.sh').read_text()
        gate='python3 -B "$stage/source/deployment/prerequisites.py" clock "$role" >/dev/null'
        self.assertEqual(source.count(gate),1)
        at=source.index(gate)
        self.assertLess(source.index('source /etc/os-release'),at)
        self.assertLess(at,source.index('docker info'))
        self.assertLess(at,source.index('case "$action" in'))
        self.assertLess(at,source.index('flock -n 9'))

    def test_clock_gate_keeps_opaque_export_bytes_clean_and_stops_on_failure(self):
        source=(ROOT/'deployment/remote.sh').read_text()
        gate=next(line for line in source.splitlines() if 'prerequisites.py" clock ' in line)
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);python=root/'python3'
            python.write_text('#!/bin/sh\n[ "$1" = -B ] && [ "$3" = clock ] && [ "$4" = security ] || exit 91\nprintf \'{"clock":"fixture"}\\n\'\nif [ "$CLOCK_TEST_STATUS" != 0 ]; then printf \'clock refused\\n\' >&2; fi\nexit "$CLOCK_TEST_STATUS"\n')
            python.chmod(0o700)
            script='set -e\nstage="$1"\nrole=security\n'+gate+'\nprintf \'opaque\\0stream\'\n'
            for status in ('0','42'):
                env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'],CLOCK_TEST_STATUS=status)
                p=subprocess.run(['bash','-c',script,'clock-stream-test',str(root)],capture_output=True,env=env)
                self.assertEqual(p.returncode,int(status),p.stderr)
                self.assertEqual(p.stdout,b'opaque\0stream' if status=='0' else b'')
                if status!='0':self.assertIn(b'clock refused',p.stderr)

    def test_certificate_actions_are_exact_and_only_for_security_and_siem(self):
        source=(ROOT/'deployment/remote.sh').read_text()
        prefix=source.split('[[ $(id -u) == 0',1)[0]+'exit 0\n'
        for role in ('siem','security','service'):
            for action in ('cert-check','cert-install','cert-verify','cert-delete','cert-install;id'):
                with self.subTest(role=role,action=action):
                    p=subprocess.run(['bash','-s','--','/var/tmp/capstone-bootstrap-'+'a'*24,role,action],input=prefix,text=True,capture_output=True)
                    self.assertEqual(p.returncode,0 if role in ('siem','security') and action in ('cert-check','cert-install','cert-verify') else 64,p.stderr)

    def test_certificate_dispatch_is_after_lock_and_role_guard(self):
        source=(ROOT/'deployment/remote.sh').read_text()
        branch='cert-*) exec python3 -B'
        self.assertEqual(source.count(branch),1)
        at=source.index(branch)
        self.assertLess(source.index('flock -n 9'),at)
        self.assertLess(source.index('$(cat "$CAPSTONE_ROOT/role") == "$role"'),at)

    def test_review_actions_only_siem_and_exact_names(self):
        source=(ROOT/'deployment/remote.sh').read_text()
        boundary='[[ $(id -u) == 0'
        self.assertEqual(source.count(boundary),1)
        prefix=source.split(boundary,1)[0]+'exit 0\n'
        for role in ('siem','security','service'):
            for action in ('review-chat-install','review-chat-verify','review-chat-delete','review-chat-install;id'):
                with self.subTest(role=role,action=action):
                    p=subprocess.run(['bash','-s','--','/var/tmp/capstone-bootstrap-'+'a'*24,role,action],input=prefix,text=True,capture_output=True)
                    expected=0 if role=='siem' and action in ('review-chat-install','review-chat-verify') else 64
                    self.assertEqual(p.returncode,expected,p.stderr)

if __name__=='__main__':unittest.main()
