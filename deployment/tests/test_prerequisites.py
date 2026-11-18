import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prereqs', ROOT / 'prerequisites.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
spec2 = importlib.util.spec_from_file_location('site', ROOT / 'validate_lab_site.py')
site = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(site)

class Artifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'artifacts.json'
        self.doc = {'schema': 1, 'role': 'service', 'packages': [], 'images': []}
    def read(self):
        self.path.write_text(json.dumps(self.doc))
        with patch.object(m, 'safe', side_effect=Path): return m.read_manifest(self.path, 'service')
    def package(self):
        p = self.path.parent / 'test.deb'; p.write_bytes(b'deb-fixture')
        return {'file': p.name, 'sha256': m.sha(p), 'package': 'example', 'version': '1.0', 'architecture': 'amd64'}
    def test_empty_inventory_allows_preinstalled_hosts(self): self.assertEqual(self.read(), self.doc)
    def test_wrong_host_role_rejected(self):
        self.doc['role'] = 'security'
        with self.assertRaises(m.Refused): self.read()
    def test_traversal_rejected_before_command(self):
        p = self.package(); p['file'] = '../test.deb'; self.doc['packages'] = [p]
        with patch.object(m, 'run') as run, self.assertRaises(m.Refused): self.read()
        run.assert_not_called()
    def test_checksum_checked_before_package_metadata(self):
        p = self.package(); p['sha256'] = '0'*64; self.doc['packages'] = [p]
        with patch.object(m, 'run') as run, self.assertRaises(m.Refused): self.read()
        run.assert_not_called()
    def test_metadata_substitution_rejected(self):
        self.doc['packages'] = [self.package()]
        with patch.object(m, 'run', return_value=subprocess.CompletedProcess([], 0, b'Package: other\nVersion: 1.0\nArchitecture: amd64\n')), self.assertRaises(m.Refused): self.read()
    def test_invalid_image_identity_rejected(self):
        p = self.path.parent / 'image.tar'; p.write_bytes(b'fixture')
        self.doc['images'] = [{'file':p.name,'sha256':m.sha(p),'tag':'lab:1','image_id':'latest'}]
        with self.assertRaises(m.Refused): self.read()
    def test_existing_wrong_image_never_replaced(self):
        doc = dict(self.doc, images=[{'file':'image.tar','sha256':'0'*64,'tag':'lab:1','image_id':'sha256:'+'a'*64}])
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,b'sha256:'+b'b'*64+b' linux amd64\n')
        with patch.object(m,'run',side_effect=run), self.assertRaises(m.Refused): m.install(self.path,doc)
        self.assertFalse(any('load' in c for c in calls))
    def test_unlisted_apt_dependency_stops_before_install(self):
        doc = dict(self.doc, packages=[self.package()]); calls=[]
        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args,1,b'') if args[0]=='dpkg-query' else subprocess.CompletedProcess(args,0,b'Inst unapproved (2.0 repository)\n')
        with patch.object(m,'run',side_effect=run), patch.object(m,'safe',side_effect=Path), self.assertRaises(m.Refused):m.install(self.path,doc)
        self.assertEqual(sum(c[0]=='apt-get' for c in calls),1)
        self.assertIn('--simulate',calls[-1]);self.assertIn('--no-download',calls[-1])
    def test_downgrade_stops_before_apt(self):
        doc=dict(self.doc,packages=[self.package()]);calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,b'install ok installed\t2.0' if args[0]=='dpkg-query' else b'')
        with patch.object(m,'run',side_effect=run),self.assertRaises(m.Refused):m.install(self.path,doc)
        self.assertFalse(any(c[0]=='apt-get' for c in calls))
    def test_offline_cache_uses_canonical_epoch_name_and_is_removed(self):
        item = self.package(); item['version'] = '1:1.0'
        doc = dict(self.doc, packages=[item]); calls = []; cache_paths = []
        def run(args, **kwargs):
            calls.append(args)
            if args[0] == 'dpkg-query':
                installed = any(c[0] == 'apt-get' and '--simulate' not in c for c in calls)
                return subprocess.CompletedProcess(args, 0 if installed else 1,
                    b'install ok installed\t1:1.0' if installed else b'')
            if args[0] == 'apt-get':
                self.assertIn('--no-download', args)
                cache = Path(next(x.split('=',1)[1] for x in args if x.startswith('Dir::Cache::archives=')))
                target = cache / 'example_1%3a1.0_amd64.deb'
                self.assertEqual(target.read_bytes(), b'deb-fixture')
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                cache_paths.append(cache)
                return subprocess.CompletedProcess(args, 0, b'Inst example (1:1.0 local)\n')
            raise AssertionError(args)
        with patch.object(m, 'run', side_effect=run), patch.object(m, 'safe', side_effect=Path): m.install(self.path, doc)
        self.assertEqual(len(cache_paths), 2)
        self.assertFalse(cache_paths[0].exists())

    def test_failed_offline_simulation_removes_its_private_cache(self):
        item = self.package(); caches = []
        def run(args, **kwargs):
            if args[0] == 'dpkg-query': return subprocess.CompletedProcess(args, 1, b'')
            caches.append(Path(next(x.split('=',1)[1] for x in args if x.startswith('Dir::Cache::archives='))))
            raise m.Refused('simulation failed')
        with patch.object(m, 'run', side_effect=run), patch.object(m, 'safe', side_effect=Path), self.assertRaises(m.Refused):
            m.install(self.path, dict(self.doc, packages=[item]))
        self.assertFalse(caches[0].exists())
    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(m.Refused):json.loads('{"schema":1,"schema":2}',object_pairs_hook=m.pairs)

class Site(unittest.TestCase):
    def test_valid_private_tls_site(self):
        x=site.validate('https://lab.example.org:9443','9443','192.168.10.0/24','172.30.247.0/29')
        self.assertEqual(x['authority'],'lab.example.org:9443');self.assertEqual(x['edge_ip'],'172.30.247.3')
    def test_untrusted_or_ambiguous_input(self):
        base=['https://lab.example.org','443','192.168.10.0/24','172.30.247.0/29']
        for index,value in [(0,'http://lab.example.org'),(0,'https://lab.example.org/'),(0,'https://lab.example.org;return'),(0,'https://user:secret@lab.example.org'),(0,'https://127.0.0.1'),(1,'8443'),(2,'0.0.0.0/0'),(2,'192.168.10.1/24'),(3,'192.168.10.0/29'),(3,'172.30.247.0/24')]:
            with self.subTest(value=value):
                args=base[:];args[index]=value
                with self.assertRaises(ValueError):site.validate(*args)

class HostSecurityBaseline(unittest.TestCase):
    def result(self, args, **kwargs):
        if args[0] == 'dpkg-query':
            return subprocess.CompletedProcess(args, 0, b'install ok installed\t1.8.31-1ubuntu1')
        version = args[2]
        return subprocess.CompletedProcess(args, 0 if version in (
            '1.9.15p5-3ubuntu5.24.04.4', '1.9.15p5-3ubuntu5.24.04.5') else 1, b'')

    def test_preinstalled_vulnerable_host_is_rejected(self):
        with patch.object(m, 'run', side_effect=self.result), self.assertRaises(m.Refused):
            m.security_baseline({'packages': []})

    def test_approved_fixed_host_artifact_can_replace_old_package(self):
        for version in ('1.9.15p5-3ubuntu5.24.04.4', '1.9.15p5-3ubuntu5.24.04.5'):
            with self.subTest(version=version), patch.object(m, 'run', side_effect=self.result):
                m.security_baseline({'packages': [{'package': 'sudo', 'version': version}]})

    def test_old_noble_and_focal_host_artifacts_are_rejected(self):
        for version in ('1.8.31-1ubuntu1', '1.9.15p5-3ubuntu5.24.04.2'):
            with self.subTest(version=version), patch.object(m, 'run', side_effect=self.result), self.assertRaises(m.Refused):
                m.security_baseline({'packages': [{'package': 'sudo', 'version': version}]})

    def test_post_install_checks_actual_host_not_only_manifest(self):
        with patch.object(m, 'run', side_effect=self.result), self.assertRaises(m.Refused):
            m.security_baseline({'packages': [{'package': 'sudo', 'version': '1.9.15p5-3ubuntu5.24.04.4'}]}, installed=True)

class HostClock(unittest.TestCase):
    VALID = b'Timezone=Asia/Seoul\nNTP=yes\nNTPSynchronized=yes\nTimeUSec=observed-only\n'

    def test_OS_state_pass_is_explicitly_limited_and_read_only(self):
        with patch.object(m, 'run', return_value=subprocess.CompletedProcess([],0,self.VALID)) as runner:
            result=m.host_clock()
        self.assertEqual(result['status'],'OS_clock_precondition_passed')
        self.assertFalse(result['settings_changed'])
        self.assertIn('not measured',result['scope'])
        self.assertTrue(result['observed_at_utc'].endswith('+00:00'))
        runner.assert_called_once_with(['timedatectl','show','--all','--no-pager'],check=False,timeout=10)

    def test_missing_duplicate_and_noncanonical_properties_refuse(self):
        for raw in (b'',b'Timezone=Asia/Seoul\nNTP=yes\n',
                    self.VALID+b'NTP=yes\n',self.VALID.replace(b'NTP=yes',b'NTP=true'),
                    self.VALID.replace(b'NTPSynchronized=yes',b'NTPSynchronized=Yes')):
            with self.subTest(raw=raw),patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,raw)),self.assertRaises(m.Refused):
                m.host_clock()

    def test_client_environment_timezone_cannot_mask_host_timezone(self):
        with patch.dict(m.os.environ,{'TZ':'Asia/Seoul'}),patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,self.VALID.replace(b'Asia/Seoul',b'UTC'))),self.assertRaises(m.Refused):
            m.host_clock()

    def test_ntp_disabled_or_enabled_but_unsynchronized_refuses(self):
        for raw in (self.VALID.replace(b'NTP=yes',b'NTP=no'),
                    self.VALID.replace(b'NTPSynchronized=yes',b'NTPSynchronized=no')):
            with self.subTest(raw=raw),patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,raw)),self.assertRaises(m.Refused):
                m.host_clock()

    def test_command_failure_cannot_pass_with_cached_healthy_output(self):
        with patch.object(m,'run',return_value=subprocess.CompletedProcess([],1,self.VALID)),self.assertRaises(m.Refused):
            m.host_clock()

    def test_bad_clock_stops_before_manifest_package_or_host_mutation(self):
        for action in ('check','apply'):
            for role in ('security','siem','service'):
                raw=self.VALID.replace(b'NTPSynchronized=yes',b'NTPSynchronized=no')
                with self.subTest(action=action,role=role),patch.object(m.sys,'argv',['prerequisites.py',action,role]),patch.object(m.os,'geteuid',return_value=0),patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,raw)),patch.object(m,'fresh_host_guard') as guard,patch.object(m,'read_manifest') as manifest,patch.object(m,'security_baseline') as security,patch.object(m,'install') as install,self.assertRaises(m.Refused):
                    m.main()
                guard.assert_not_called();manifest.assert_not_called();security.assert_not_called();install.assert_not_called()

    def test_clock_only_does_not_adopt_or_install_existing_host(self):
        with patch.object(m.sys,'argv',['prerequisites.py','clock','siem']),patch.object(m.os,'geteuid',return_value=0),patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,self.VALID)),patch.object(m,'fresh_host_guard') as guard,patch.object(m,'read_manifest') as manifest,contextlib.redirect_stdout(io.StringIO()) as output:
            m.main()
        result=json.loads(output.getvalue())
        self.assertEqual(result['action'],'clock');self.assertEqual(result['role'],'siem')
        guard.assert_not_called();manifest.assert_not_called()

if __name__=='__main__':unittest.main()
