#!/usr/bin/env python3
"""Boundary tests for the isolated native rule runner; no Docker invocation."""
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('native_rules',Path(__file__).with_name('run_certificate_rules_native.py'))
N=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)


class NativeRuleBoundary(unittest.TestCase):
    def test_extended_original_cases_are_unique_and_role_bound(self):
        files,rows=N.fixtures()
        self.assertEqual(len(rows),112)
        self.assertEqual(len({(r['role'],r['name']) for r in rows}),112)
        self.assertEqual({r['expected'][0] for r in rows if r['expected']},N.IDS)
        self.assertEqual(sum(r['expected'] is None for r in rows),58)
        for role,sensor,domain in [('security','capstone-security','lab.example.org'),
                                   ('siem','capstone-siem-host','capstone-siem.internal')]:
            byname={r['name']:r for r in rows if r['role']==role}
            self.assertIn(domain,byname['expired_unavailable']['payload'])
            self.assertEqual(byname['expired_unavailable']['location'],'('+sensor+') any->journald')
            self.assertIsNone(byname['known_other_sensor']['expected'])
            self.assertIsNone(byname['known_other_domain']['expected'])
            self.assertEqual(byname['message_hostname_differs']['expected'][1],10)
        self.assertNotIn(b'&gt;',files['rules.xml'])

    def test_negative_requires_engine_consumption_and_no_diagnostic(self):
        for data,rc in [(b'',0),(b'Completed pre-decoding.\nERROR: cannot load rules',0),
                        (b'Completed pre-decoding.',1),
                        (b"Completed pre-decoding.\n id: '100311'\n",0)]:
            self.assertFalse(N.verdict(data,rc,None)['passed'])
        self.assertTrue(N.verdict(b"Completed pre-decoding.\n id: '1002'\n",0,None)['passed'])

    def test_positive_requires_exact_native_severity_and_decoder(self):
        raw=b"Completed pre-decoding.\n name: 'capstone_certificate_json'\n id: '100310'\n level: '10'\n"
        self.assertTrue(N.verdict(raw,0,('100310',10))['passed'])
        self.assertFalse(N.verdict(raw.replace(b"'10'",b"'5'"),0,('100310',10))['passed'])
        self.assertFalse(N.verdict(raw.replace(b'capstone_certificate_json',b'json'),0,('100310',10))['passed'])
        self.assertFalse(N.verdict(raw+b'WARNING: Ignored rule\n',0,('100310',10))['passed'])

    def test_delete_guard_binds_identity_network_and_readonly_mounts(self):
        import copy
        fixture=Path('/var/tmp/synthetic/fixture');cid='a'*64;nonce='b'*24
        record={'Id':cid,'Image':N.IMAGE,'Config':{'Labels':{N.LABEL:nonce}},
                'HostConfig':{'NetworkMode':'none'},'Mounts':[
                    {'Type':'bind','RW':False,'Source':str(fixture/name),'Destination':destination}
                    for name,destination in N.MOUNTS]}
        self.assertTrue(N.owned_container(record,cid,nonce,fixture))
        for key,value in [('Id','c'*64),('Image','sha256:'+'d'*64)]:
            bad=copy.deepcopy(record);bad[key]=value
            self.assertFalse(N.owned_container(bad,cid,nonce,fixture))
        for mutation in ('label','network','write','foreign_source','extra_mount'):
            bad=copy.deepcopy(record)
            if mutation=='label':bad['Config']['Labels'][N.LABEL]='foreign'
            if mutation=='network':bad['HostConfig']['NetworkMode']='host'
            if mutation=='write':bad['Mounts'][0]['RW']=True
            if mutation=='foreign_source':bad['Mounts'][0]['Source']='/etc/operating.conf'
            if mutation=='extra_mount':bad['Mounts'].append({'Type':'volume','RW':True})
            self.assertFalse(N.owned_container(bad,cid,nonce,fixture),mutation)


if __name__=='__main__':
    unittest.main()
