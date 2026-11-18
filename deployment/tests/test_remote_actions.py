"""Exercise the real preflight allowlist; never reach ownership/host checks."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]

class RemoteActions(unittest.TestCase):
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
