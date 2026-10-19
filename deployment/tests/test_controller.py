#!/usr/bin/env python3
"""Exercise the real controller against a fake SSH transport; no host mutations."""
import json
import os
from pathlib import Path
import shutil
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
            'LLM_BASE_URL=http://192.0.2.40:11434/v1\n')
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        TMPDIR=str(self.root / 'tmp'), TRANSPORT_LOG=str(self.log),
                        PAYLOAD_LOG=str(self.payload_log),
                        PYTHONDONTWRITEBYTECODE='1')

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
        self.assertEqual(self.phases(), ['security check', 'siem check', 'service check',
                                        'siem apply', 'siem verify', 'service apply', 'service verify',
                                        'security apply', 'security verify', 'siem verify'])
        for event in self.events():
            self.assertIn('StrictHostKeyChecking=yes', event['args'])
            self.assertIn('BatchMode=yes', event['args'])
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
                                        'siem apply', 'siem verify', 'service apply'])
        self.assertNotIn('구축 완료.', result.stdout)
        self.assert_clean()

    def test_check_does_not_apply(self):
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.phases(), ['security check', 'siem check', 'service check'])
        self.assert_clean()

    def test_prepared_jar_path_reaches_hosts_without_uploading_jar(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_APP_JAR=/opt/capstone-prereqs/reviewed-app.jar\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('service 서버의 준비 파일 사용', result.stdout)
        self.assertNotIn('소스로 자동 빌드', result.stdout)
        for payload in self.payloads():
            self.assertIn('export LOG4SHELL_APP_JAR=/opt/capstone-prereqs/reviewed-app.jar', payload['site_env'].splitlines())
        self.assert_clean()

    def test_default_build_transfers_sources_without_local_artifacts(self):
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('service 서버에서 전달한 소스로 자동 빌드', result.stdout)
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
        self.assertIn('자동 빌드', result.stdout)
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
        self.assertEqual(self.phases(), ['siem verify', 'service verify', 'security verify'])
        self.assert_clean()

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
        self.assertIn('DVWA/MariaDB + Log4Shell', result.stdout)
        self.assertIn('요청 UI', result.stdout)
        self.assert_clean()

    def test_log4shell_image_override_reaches_staged_hosts(self):
        image = 'registry.example.org/labs/log4shell@sha256:' + 'a' * 64
        with self.config.open('a') as f:
            f.write('LOG4SHELL_IMAGE=' + image + '\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        payloads = self.payloads()
        self.assertEqual([p['host'] for p in payloads], ['192.0.2.10', '192.0.2.20', '192.0.2.30'])
        for payload in payloads:
            self.assertIn('export LOG4SHELL_IMAGE=' + image, payload['site_env'].splitlines())
        self.assert_clean()

    def test_empty_log4shell_image_keeps_role_default(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_IMAGE=\n')
        result = self.run_controller('--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.payloads()), 3)
        for payload in self.payloads():
            self.assertNotIn('LOG4SHELL_IMAGE=', payload['site_env'])
        self.assert_clean()

    def test_http_hostname_reaches_hosts_and_is_reported(self):
        with self.config.open('a') as f:
            f.write('LOG4SHELL_HOSTNAME=log4shell.example.org\nWAF_PORT=9080\n')
        result = self.run_controller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('http://log4shell.example.org:9080/', result.stdout)
        for payload in self.payloads():
            self.assertIn('export LOG4SHELL_HOSTNAME=log4shell.example.org', payload['site_env'].splitlines())
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
        self.assertIn('http://192.0.2.10:8080/log4shell/', result.stdout)
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
