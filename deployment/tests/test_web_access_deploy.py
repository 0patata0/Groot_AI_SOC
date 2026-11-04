"""Fixed web-reader deployment boundaries; fake I/O, no host mutation."""
import base64
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import web_access_deploy as d

KEY='ssh-ed25519 '+base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20'+b'x'*32).decode()
S={'source':Path('/approved/source'),'hosts':{'SECURITY_HOST':'10.42.0.1','SIEM_HOST':'10.42.0.10','SERVICE_HOST':'10.42.0.20'}}

class Contracts(unittest.TestCase):
    def test_publisher_has_fixed_input_no_network_or_actuator_and_bounded_resources(self):
        docs=d.unit_documents();self.assertEqual(set(docs),{d.SERVICE,d.TIMER})
        service=docs[d.SERVICE].decode()
        for item in ('-IB /opt/capstone-web-evidence/web_evidence.py --collect','NoNewPrivileges=yes',
                     'ProtectSystem=strict','RestrictAddressFamilies=AF_UNIX','CapabilityBoundingSet=\n',
                     'ReadWritePaths=/var/lib/capstone-web-evidence','MemoryMax=96M','TimeoutStartSec=30'):
            self.assertIn(item,service)
        for forbidden in ('sudo','docker','curl','journalctl'):
            self.assertNotIn(forbidden,service)
        self.assertIn('OnUnitActiveSec=60s',docs[d.TIMER].decode())

    def test_reader_refuses_arguments_and_original_command_and_clears_environment(self):
        script=d.launcher().decode()
        self.assertIn('[ "$#" -eq 0 ]',script);self.assertIn('SSH_ORIGINAL_COMMAND',script)
        self.assertIn('/usr/bin/env -i',script);self.assertNotIn('sudo',script)
        config=d.ssh_configuration().decode()
        for text in ('ForceCommand /opt/capstone-web-evidence/read','AuthenticationMethods publickey',
                     'PasswordAuthentication no','DisableForwarding yes','PermitTTY no'):
            self.assertIn(text,config)
        self.assertNotIn('PermitUserEnvironment',config)  # global-only on supported sshd

    def test_source_bundle_parses_all_code_before_install(self):
        with patch.object(d.common,'read',return_value=b'# valid\n'):
            self.assertEqual(set(d.source_bundle(S)),set(d.SOURCES)|{'web_access_deploy.py'})
        with patch.object(d.common,'read',return_value=b'def invalid(:\n'),self.assertRaises(SyntaxError):
            d.source_bundle(S)

    def test_existing_install_is_verified_without_recreating_account_or_key(self):
        with patch.object(d.sys,'platform','linux'),patch.object(d.os,'geteuid',return_value=0), \
             patch.object(d,'source_bundle',return_value={}),patch.object(d.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=984)), \
             patch.object(Path,'exists',return_value=True),patch.object(d,'verify',return_value={'status':'ready'}) as verify, \
             patch.object(d.common,'run') as run,patch.object(d.common,'write') as write:
            self.assertEqual(d.install_service(S,KEY),{'status':'ready'})
        verify.assert_called_once_with(S,KEY);run.assert_not_called();write.assert_not_called()

    def test_namespace_collision_is_rejected_before_account_or_file_changes(self):
        with patch.object(d.sys,'platform','linux'),patch.object(d.os,'geteuid',return_value=0), \
             patch.object(d,'source_bundle',return_value={}),patch.object(d.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=984)), \
             patch.object(Path,'exists',return_value=False),patch.object(d.os.path,'lexists',return_value=True), \
             patch.object(d.common,'run') as run,patch.object(d.common,'write') as write,self.assertRaises(ValueError):
            d.install_service(S,KEY)
        run.assert_not_called();write.assert_not_called()

    def test_fresh_install_only_creates_forced_reader_and_publisher(self):
        writes=[];commands=[]
        bundle={name:b'# approved\n' for name in (*d.SOURCES,'web_access_deploy.py')}
        with patch.object(d.sys,'platform','linux'),patch.object(d.os,'geteuid',return_value=0), \
             patch.object(d,'source_bundle',return_value=bundle),patch.object(d.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=984)), \
             patch.object(Path,'exists',return_value=False),patch.object(d.os.path,'lexists',return_value=False), \
             patch.object(d.pwd,'getpwnam',side_effect=KeyError),patch.object(d.common,'mkdir'), \
             patch.object(d.common,'write',side_effect=lambda p,raw,*a:writes.append((str(p),raw))), \
             patch.object(d.common,'run',side_effect=lambda argv,**kw:commands.append(argv)), \
             patch.object(d,'record',return_value={'sha256':'f'*64,'mode':0o640,'gid':984}), \
             patch.object(d,'verify',return_value={'status':'ready'}):
            self.assertEqual(d.install_service(S,KEY)['status'],'ready')
        keys=next(raw.decode() for p,raw in writes if p.endswith('/authorized_keys'))
        self.assertIn('from="10.42.0.10",restrict,command="/opt/capstone-web-evidence/read"',keys)
        self.assertIn(KEY,keys)
        self.assertFalse(any('sudoers' in p or 'id_ed25519' in p for p,_ in writes))
        self.assertFalse(any('docker' in ' '.join(c) or 'restart' in c for c in commands))
        self.assertTrue(any(c[-2:]==['start',d.SERVICE] for c in commands))

if __name__=='__main__':unittest.main()
