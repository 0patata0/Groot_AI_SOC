"""Exercise the real preflight allowlist; never reach ownership/host checks."""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]

class RemoteActions(unittest.TestCase):
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
