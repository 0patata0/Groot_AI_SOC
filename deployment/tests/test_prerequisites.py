import importlib.util
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
        with patch.object(m,'run',side_effect=run), self.assertRaises(m.Refused):m.install(self.path,doc)
        self.assertEqual(sum(c[0]=='apt-get' for c in calls),1)
        self.assertIn('--simulate',calls[-1]);self.assertIn('--no-download',calls[-1])
    def test_downgrade_stops_before_apt(self):
        doc=dict(self.doc,packages=[self.package()]);calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args,0,b'install ok installed\t2.0' if args[0]=='dpkg-query' else b'')
        with patch.object(m,'run',side_effect=run),self.assertRaises(m.Refused):m.install(self.path,doc)
        self.assertFalse(any(c[0]=='apt-get' for c in calls))
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

if __name__=='__main__':unittest.main()
