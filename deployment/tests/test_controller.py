#!/usr/bin/env python3
"""Exercise the real controller against a fake SSH transport; no host mutations."""
import json
import os
import pty
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FAKE_SSH = r'''#!/usr/bin/env python3
import io,json,os,sys,tarfile
from pathlib import Path
args=sys.argv[1:]
host=next(x.split('@',1)[1] for x in args if x.startswith('ubuntu@'))
command=args[-1]
with open(os.environ['TRANSPORT_LOG'],'a') as f:
    f.write(json.dumps({'host':host,'command':command,'args':args})+'\n')
if command=='cat /etc/machine-id':
    print(('a' if os.environ.get('SAME_HOST') else {'192.0.2.10':'a','192.0.2.20':'b','192.0.2.30':'c'}[host])*32)
elif '/deployment/remote.sh ' in command:
    phase=' '.join(command.split()[-2:])
    if os.environ.get('FAIL_PHASE')==phase: sys.exit(42)
    if phase=='siem soc-export': sys.stdout.buffer.write(b'private-soc-test-stream')
    elif phase=='security soc-receive':
        if sys.stdin.buffer.read()!=b'private-soc-test-stream': sys.exit(48)
    elif phase=='security soc-apply': sys.stdout.buffer.write(b'public-host-identity')
    elif phase=='siem soc-activate':
        if sys.stdin.buffer.read()!=b'public-host-identity': sys.exit(49)
    elif phase=='siem diag-export': sys.stdout.buffer.write(b'diagnostic-public-key-stream')
    elif phase in ('security diag-apply','service diag-apply'):
        if sys.stdin.buffer.read()!=b'diagnostic-public-key-stream': sys.exit(50)
        print(json.dumps({'role':phase.split()[0],'host_key':'public-diagnostic-host-key'}))
    elif phase=='siem diag-activate':
        evidence=json.loads(sys.stdin.buffer.read())
        if [x['role'] for x in evidence]!=['security','service']: sys.exit(51)
elif '/deployment/prerequisites.py ' in command:
    if os.environ.get('FAIL_BUNDLE') == ' '.join(command.split()[-2:]): sys.exit(45)
elif '/deployment/lab_key.py check' in command:
    if os.environ.get('FAIL_COMMON_KEY'): sys.exit(47)
elif '/deployment/lab_key.py export' in command:
    sys.stdout.buffer.write(b'test-common-key')
elif '/deployment/lab_key.py receive' in command:
    if sys.stdin.buffer.read()!=b'test-common-key': sys.exit(46)
elif 'tar -cf - exports/' in command:
    sys.stdout.buffer.write(b'enrollment-test-stream')
elif 'tar --no-same-owner -xf -' in command or '/receive-enrollment.sh' in command:
    data=sys.stdin.buffer.read()
    if '/receive-enrollment.sh' in command and data!=b'enrollment-test-stream': sys.exit(43)
    if 'tar --no-same-owner -xf -' in command:
        with tarfile.open(fileobj=io.BytesIO(data)) as outer:
            source=outer.extractfile('source.tar').read()
            site_env=outer.extractfile('site.env').read().decode()
        with tarfile.open(fileobj=io.BytesIO(source)) as archive:
            names=archive.getnames()
        with open(os.environ['PAYLOAD_LOG'],'a') as f:
            f.write(json.dumps({'host':host,'site_env':site_env,'source_names':names})+'\n')
        if any('CREDENTIALS' in n or n.endswith(('.env','.key','.pem','.local.conf','.jar','.class')) for n in names): sys.exit(44)
'''


class ControllerContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='capstone-controller-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copy2(ROOT / 'deploy.sh', self.root / 'deploy.sh')
        for name in ('deployment', 'infra', 'new_rule', 'bin', 'tmp'):
            (self.root / name).mkdir()
        shutil.copy2(ROOT / 'deployment/validate_lab_site.py', self.root / 'deployment/validate_lab_site.py')
        shutil.copy2(ROOT / 'deployment/protected_hosts.py', self.root / 'deployment/protected_hosts.py')
        (self.root / 'infra' / 'CREDENTIALS.local.md').write_text('must-not-transfer')
        (self.root / 'infra' / '.env').write_text('must-not-transfer')
        (self.root / 'infra' / 'prepared.jar').write_text('must-not-transfer')
        (self.root / 'infra' / 'compiled.class').write_text('must-not-transfer')
        app = self.root / 'infra/groot-c/log4shell-app'
        for name in ('src/main/java/fr/christophetd/log4shell/vulnerableapp/MainController.java',
                     'src/main/resources/static/index.html', 'src/main/resources/application.properties',
                     'tools/build_from_existing.py', 'tools/prepare_from_image.py', 'build.gradle', 'settings.gradle',
                     'build/local-output', '.gradle/local-cache'):
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('source fixture')
        (self.root / 'deployment' / 'siem-secrets.env').write_text('must-not-transfer')
        (self.root / 'deployment' / 'site.local.conf').write_text('must-not-transfer')
        (self.root / 'deployment' / 'private.key').write_text('must-not-transfer')
        self.known = self.root / 'known_hosts'
        self.known.write_text('fixture host keys\n')
        self.log = self.root / 'transport.jsonl'
        self.payload_log = self.root / 'payload.jsonl'
        ssh = self.root / 'bin' / 'ssh'
        ssh.write_text(FAKE_SSH)
        ssh.chmod(0o700)
        self.config = self.root / 'site.conf'
        self.config.write_text(
            'SECURITY_HOST=192.0.2.10\nSIEM_HOST=192.0.2.20\nSERVICE_HOST=192.0.2.30\n'
            'SSH_USER=ubuntu\nSSH_KNOWN_HOSTS=' + str(self.known) + '\n'
            'LLM_BASE_URL=http://192.0.2.40:11434/v1\n'
            'LAB_PUBLIC_ORIGIN=https://lab.example.org\nLAB_ALLOWED_CIDRS=192.168.10.0/24\n')
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        TMPDIR=str(self.root / 'tmp'), TRANSPORT_LOG=str(self.log),
                        PAYLOAD_LOG=str(self.payload_log),
                        PYTHONDONTWRITEBYTECODE='1')

    def test_optional_ollama_trial_is_siem_only_after_diagnostics(self):
        with self.config.open('a') as f:
            f.write('OLLAMA_TRIAL_ENABLE=1\n')
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        phases = self.phases()
        self.assertLess(phases.index('siem trial-check'), phases.index('siem apply'))
        self.assertLess(phases.index('siem diag-activate'), phases.index('siem trial-install'))
        self.assertLess(phases.index('siem trial-install'), phases.index('siem trial-verify'))
        self.assertFalse(any(x.startswith(('security trial-', 'service trial-')) for x in phases))

    def test_trial_check_failure_stops_install(self):
        with self.config.open('a') as f:
            f.write('OLLAMA_TRIAL_ENABLE=1\n')
        result = self.run_controller(FAIL_PHASE='siem trial-check')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('siem trial-install', self.phases())

    def test_trial_flag_rejects_shell_text_before_ssh(self):
        with self.config.open('a') as f:
            f.write('OLLAMA_TRIAL_ENABLE=1;touch /tmp/no\n')
        result = self.run_controller('--plan')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_optional_chat_follows_verified_runtime(self):
        with self.config.open('a') as f:
            f.write('OLLAMA_TRIAL_ENABLE=1\nOLLAMA_TRIAL_CHAT_ENABLE=1\n')
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        phases = self.phases()
        self.assertLess(phases.index('siem trial-verify'), phases.index('siem trial-chat-install'))
        self.assertLess(phases.index('siem trial-chat-install'), phases.index('siem trial-chat-verify'))

    def test_chat_without_runtime_rejected_before_ssh(self):
        with self.config.open('a') as f:
            f.write('OLLAMA_TRIAL_CHAT_ENABLE=1\n')
        result = self.run_controller('--plan')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def run_controller(self, mode='--apply', **env):
        return subprocess.run(['bash', str(self.root / 'deploy.sh'), mode, '--batch', '--config', str(self.config)],
                              env=dict(self.env, **env), capture_output=True, text=True, timeout=30)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def phases(self):
        return [' '.join(e['command'].split()[-2:]) for e in self.events()
                if '/deployment/remote.sh ' in e['command']]

    def payloads(self):
        return [json.loads(line) for line in self.payload_log.read_text().splitlines()] if self.payload_log.exists() else []

    def assert_clean(self):
        self.assertEqual(list((self.root / 'tmp').iterdir()), [])

    def test_dependency_order_and_strict_ssh(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        phases = self.phases()
        self.assertEqual(phases[:6], ['security check', 'siem check', 'service check',
                                     'security soc-check', 'siem soc-check', 'siem dashboard-check'])
        for earlier, later in [('siem apply','service apply'), ('service verify','security apply'),
                               ('security verify','siem soc-prepare'), ('siem soc-prepare','security soc-apply'),
                               ('security soc-apply','security log-activate'), ('security log-activate','siem log-monitor'),
                               ('siem log-monitor','siem dashboard-apply'), ('siem dashboard-apply','siem soc-activate')]:
            self.assertLess(phases.index(earlier), phases.index(later))
        self.assertEqual(phases[-10:], ['security soc-verify','security log-verify','siem verify',
                                      'siem soc-verify','siem log-verify','siem dashboard-verify',
                                      'security diag-verify','service diag-verify','siem diag-verify','siem tls-verify'])
        self.assertLess(phases.index('siem tls-install'),phases.index('siem soc-prepare'))
        self.assertLess(phases.index('security tls-trust'),phases.index('security soc-apply'))
        self.assertLess(phases.index('service host-verify'),phases.index('security soc-verify'))
        for earlier, later in [('siem soc-activate','siem diag-prepare'),
                               ('siem diag-prepare','security diag-apply'),
                               ('security diag-apply','service diag-apply'),
                               ('service diag-apply','siem diag-activate'),
                               ('siem diag-activate','siem diag-verify')]:
            self.assertLess(phases.index(earlier), phases.index(later))
        for event in self.events():
            self.assertIn('StrictHostKeyChecking=yes', event['args'])
            self.assertIn('BatchMode=yes', event['args'])
        self.assert_clean()

    def test_nonweb_bundle_path_is_data_and_exported_to_roles(self):
        with self.config.open('a') as stream:
            stream.write('LAB_NONWEB_BUNDLE=/opt/reviewed/nonweb\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        for payload in self.payloads():
            self.assertIn('export LAB_NONWEB_BUNDLE=/opt/reviewed/nonweb', payload['site_env'].splitlines())
        self.assert_clean()

    def test_nonweb_bundle_relative_traversal_and_shell_text_rejected_before_ssh(self):
        original = self.config.read_text()
        for value in ('relative/nonweb', '/opt/../etc', '/opt/nonweb;id', '/opt/nonweb$(id)'):
            with self.subTest(value=value):
                self.config.write_text(original + 'LAB_NONWEB_BUNDLE=' + value + '\n')
                result = self.run_controller('--check')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events(), [])
                self.assert_clean()

    def test_failed_prerequisite_prevents_every_apply(self):
        result = self.run_controller(FAIL_PHASE='service check')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.phases(), ['security check', 'siem check', 'service check'])
        self.assert_clean()

    def test_failed_siem_prevents_agent_or_waf_installation(self):
        result = self.run_controller(FAIL_PHASE='siem verify')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('service apply', self.phases())
        self.assertNotIn('security apply', self.phases())
        self.assert_clean()

    def test_failed_service_apply_stops_later_roles_after_siem(self):
        result = self.run_controller(FAIL_PHASE='service apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.phases(), ['security check', 'siem check', 'service check',
                                        'security soc-check', 'siem soc-check', 'siem dashboard-check',
                                        'security diag-check','siem diag-check','service diag-check',
                                        'service host-check','siem host-check',
                                        'siem apply', 'siem verify', 'service apply'])
        self.assertNotIn('구축 완료.', result.stdout)
        self.assert_clean()

    def test_internal_tls_failure_prevents_approval_transport_activation(self):
        result = self.run_controller(FAIL_PHASE='siem tls-install')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('siem soc-prepare',self.phases())
        self.assertNotIn('security soc-apply',self.phases())
        self.assert_clean()

    def test_check_does_not_apply(self):
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.phases(), ['security check', 'siem check', 'service check',
                                        'security soc-check', 'siem soc-check', 'siem dashboard-check',
                                        'security diag-check','siem diag-check','service diag-check',
                                        'service host-check','siem host-check'])
        self.assert_clean()

    def test_legacy_build_override_is_rejected_before_ssh(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_APP_JAR=/opt/capstone-prereqs/reviewed-app.jar\n')
        result = self.run_controller('--check')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('retired', result.stderr)
        self.assertEqual(self.events(), [])

    def test_default_build_transfers_sources_without_local_artifacts(self):
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Lab Console', result.stdout)
        self.assertEqual(len(self.payloads()), 3)
        prefix = 'infra/groot-c/log4shell-app/'
        for payload in self.payloads():
            self.assertNotIn('LOG4SHELL_APP_JAR=', payload['site_env'])
            names = payload['source_names']
            for name in ('src/main/java/fr/christophetd/log4shell/vulnerableapp/MainController.java',
                         'src/main/resources/static/index.html', 'src/main/resources/application.properties',
                         'tools/build_from_existing.py', 'tools/prepare_from_image.py', 'build.gradle', 'settings.gradle'):
                self.assertIn(prefix + name, names)
            self.assertFalse(any(name.startswith((prefix + 'build/', prefix + '.gradle/')) for name in names))
        self.assert_clean()

    def test_empty_jar_override_selects_automatic_build(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_APP_JAR=\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('웹 실습3개', result.stdout)
        for payload in self.payloads():
            self.assertNotIn('LOG4SHELL_APP_JAR=', payload['site_env'])
        self.assert_clean()

    def test_prepared_jar_path_rejects_relative_traversal_and_shell_text(self):
        original = self.config.read_text()
        for value in ('relative.jar', '/opt/../tmp/app.jar', '/opt/x;touch.jar', '/opt/app.jar\nPATH=/bad', 'auto'):
            with self.subTest(value=value):
                self.config.write_text(original + 'LOG4SHELL_APP_JAR=' + value + '\n')
                result = self.run_controller('--plan')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events(), [])

    def test_verify_does_not_apply(self):
        result = self.run_controller('--verify')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.phases(), ['siem verify', 'service verify', 'security verify',
                                        'security soc-verify', 'security log-verify',
                                        'siem soc-verify', 'siem log-verify', 'siem dashboard-verify',
                                        'security diag-verify','service diag-verify','siem diag-verify',
                                        'siem tls-verify','service host-verify','siem host-verify'])
        self.assert_clean()

    def test_soc_streams_never_appear_in_outputs_or_arguments(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        for marker in ('private-soc-test-stream', 'public-host-identity', 'diagnostic-public-key-stream', 'public-diagnostic-host-key'):
            self.assertNotIn(marker, result.stdout + result.stderr + str(self.events()))
        self.assert_clean()

    def test_extension_preflight_failure_prevents_role_install(self):
        result = self.run_controller(FAIL_PHASE='security soc-check')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('siem apply', self.phases())
        self.assert_clean()

    def test_diagnostic_preflight_failure_prevents_every_role_install(self):
        result = self.run_controller(FAIL_PHASE='service diag-check')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('siem apply', self.phases())
        self.assertNotIn('siem diag-prepare', self.phases())
        self.assert_clean()

    def test_failed_diagnostic_reader_prevents_transport_activation_and_complete(self):
        result = self.run_controller(FAIL_PHASE='service diag-apply')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('security diag-apply', self.phases())
        self.assertNotIn('siem diag-activate', self.phases())
        self.assertNotIn('구축 완료.', result.stdout)
        self.assert_clean()

    def test_failed_extension_never_reports_complete(self):
        result = self.run_controller(FAIL_PHASE='security log-activate')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('siem dashboard-apply', self.phases())
        self.assertNotIn('구축 완료.', result.stdout)
        self.assert_clean()

    def test_protected_addresses_transferred_as_canonical_data(self):
        with self.config.open('a') as f:
            f.write('LOG_PROTECTED_IPS=192.0.2.70,192.0.2.10\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        for payload in self.payloads():
            line=next(line for line in payload['site_env'].splitlines() if line.startswith('export LOG_PROTECTED_IPS='))
            self.assertEqual(shlex.split(line)[1], 'LOG_PROTECTED_IPS=192.0.2.10,192.0.2.20,192.0.2.30,192.0.2.40,192.0.2.70')

    def test_hostname_llm_requires_explicit_protection_before_network(self):
        with self.config.open('a') as f:
            f.write('LLM_BASE_URL=http://llm.example.org:11434/v1\n')
        result = self.run_controller('--plan')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_admin_blank_is_optional_and_reported(self):
        result=self.run_controller('--plan')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('관리자 IP 차단 예외: 추가 지정 없음',result.stdout)
        with self.config.open('a') as f:f.write('ADMIN_PROTECTED_CIDRS=\n')
        result=self.run_controller('--check')
        self.assertEqual(result.returncode,0,result.stderr)
        for payload in self.payloads():
            line=next(x for x in payload['site_env'].splitlines() if x.startswith('export ADMIN_PROTECTED_CIDRS='))
            self.assertEqual(shlex.split(line)[1],'ADMIN_PROTECTED_CIDRS=')

    def test_admin_ip_and_network_are_canonicalized_for_every_host(self):
        with self.config.open('a') as f:f.write('ADMIN_PROTECTED_CIDRS=198.51.100.25,192.168.15.42/24\n')
        result=self.run_controller('--check')
        self.assertEqual(result.returncode,0,result.stderr)
        for payload in self.payloads():
            line=next(x for x in payload['site_env'].splitlines() if x.startswith('export ADMIN_PROTECTED_CIDRS='))
            self.assertEqual(shlex.split(line)[1],'ADMIN_PROTECTED_CIDRS=192.168.15.0/24,198.51.100.25/32')

    def test_invalid_admin_network_stops_before_ssh(self):
        with self.config.open('a') as f:f.write('ADMIN_PROTECTED_CIDRS=0.0.0.0/0\n')
        result=self.run_controller('--check')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.events(),[])

    def test_interactive_admin_prompt_accepts_empty_enter(self):
        master,slave=pty.openpty()
        try:
            os.write(master,b'\n')
            result=subprocess.run(['bash',str(self.root/'deploy.sh'),'--plan','--config',str(self.config)],
                                  stdin=slave,capture_output=True,text=True,env=self.env,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('없으면 Enter',result.stderr)
            self.assertIn('관리자 IP 차단 예외: 추가 지정 없음',result.stdout)
        finally:
            os.close(master);os.close(slave)

    def test_duplicate_host_identity_is_rejected_before_role_checks(self):
        result = self.run_controller(SAME_HOST='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.phases(), [])
        self.assert_clean()

    def test_config_is_not_executed(self):
        marker = self.root / 'injected'
        with self.config.open('a') as f:
            f.write('SECURITY_HOST=$(touch ' + str(marker) + ')\n')
        result = self.run_controller('--plan')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.events(), [])

    def test_unknown_config_key_cannot_override_path(self):
        with self.config.open('a') as f:
            f.write('PATH=/tmp\n')
        result = self.run_controller('--plan')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_plan_has_no_network_or_staging(self):
        result = self.run_controller('--plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [])
        self.assertIn('독립 DVWA/MariaDB + Lab Console', result.stdout)
        self.assert_clean()

    def test_legacy_image_override_rejected(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_IMAGE=sha256:' + 'a' * 64 + '\n')
        result = self.run_controller('--check')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_empty_log4shell_image_keeps_role_default(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_IMAGE=\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.payloads()), 3)
        for payload in self.payloads():
            self.assertNotIn('LOG4SHELL_IMAGE=', payload['site_env'])
        self.assert_clean()

    def test_https_origin_reaches_hosts_and_is_reported(self):
        with self.config.open('a') as f:
            f.write('LAB_PUBLIC_ORIGIN=https://log4shell.example.org:9443\nLAB_HTTPS_PORT=9443\n')
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('https://log4shell.example.org:9443/log4shell/', result.stdout)
        for payload in self.payloads():
            self.assertIn('export LAB_PUBLIC_ORIGIN=https://log4shell.example.org:9443', payload['site_env'].splitlines())
        self.assert_clean()

    def test_all_bundles_checked_before_first_package_install(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        actions = [' '.join(e['command'].split()[-2:]) for e in self.events() if '/deployment/prerequisites.py ' in e['command']]
        self.assertEqual(actions, ['check security', 'check siem', 'check service', 'apply security', 'apply siem', 'apply service'])

    def test_bad_bundle_prevents_packages_and_roles(self):
        result = self.run_controller(FAIL_BUNDLE='check service')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.phases(), [])
        self.assertFalse(any('/deployment/prerequisites.py apply' in e['command'] for e in self.events()))
        self.assert_clean()

    def test_common_key_uses_stream_only_after_siem_verify(self):
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        exported = next(i for i,e in enumerate(events) if '/lab_key.py export' in e['command'])
        verified = next(i for i,e in enumerate(events) if e['command'].endswith('siem verify'))
        self.assertGreater(exported, verified)
        self.assertFalse(any('test-common-key' in str(e) for e in events))
        self.assertNotIn('test-common-key', result.stdout + result.stderr)

    def test_bad_common_key_prevents_package_or_role_install(self):
        result = self.run_controller(FAIL_COMMON_KEY='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.phases(), [])
        self.assertFalse(any('/deployment/prerequisites.py apply' in e['command'] for e in self.events()))
        self.assert_clean()

    def test_hostname_invalid_values_are_rejected_before_ssh(self):
        original = self.config.read_text()
        for value in ('https://lab.example.org','lab.example.org:80','192.0.2.10','*.example.org','bad..org','UPPER.example.org'):
            with self.subTest(value=value):
                self.config.write_text(original + 'LOG4SHELL_HOSTNAME=' + value + '\n')
                result = self.run_controller('--plan')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events(), [])

    def test_empty_hostname_preserves_ip_path_and_default_role(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_HOSTNAME=\n')
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('https://lab.example.org/log4shell/', result.stdout)
        for payload in self.payloads():
            self.assertNotIn('LOG4SHELL_HOSTNAME=', payload['site_env'])
        self.assert_clean()

    def test_url_credentials_rejected_without_echo(self):
        with self.config.open('a') as f:
            f.write('LLM_BASE_URL=http://person:secretvalue@example.com/v1\n')
        result = self.run_controller('--plan')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('secretvalue', result.stdout + result.stderr)
        self.assertEqual(self.events(), [])


if __name__ == '__main__':
    unittest.main()
