#!/usr/bin/env python3
"""Pure source/config/oracle checks; no nginx, network, Docker or SSH calls."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('imperva_probe',HERE/'run-native.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class Contract(unittest.TestCase):
    def material(self):
        r=p.ROOT;c=p.CRS
        return {r+'/setup.conf':f'Include {r}/modsecurity.conf\nInclude {r}/modsecurity-override.conf\nInclude {c}/crs-setup.conf\nInclude {c}/plugins/*-config.conf\nInclude {c}/plugins/*-before.conf\nInclude {c}/rules/*.conf\nInclude {c}/plugins/*-after.conf\n'.encode(),
                r+'/modsecurity.conf':b'SecRuleEngine DetectionOnly\nSecAuditEngine RelevantOnly\nSecAuditLog /var/log/modsecurity/audit.log\nSecDataDir /tmp/modsecurity/data\n',
                r+'/modsecurity-override.conf':(p.POINTER+'\n').encode(),
                c+'/crs-setup.conf':b'# public setup\n',
                p.EXCEPTION:(HERE.parent/'REQUEST-900-CAPSTONE-SCANNER.conf').read_bytes(),
                c+'/rules/REQUEST-920-PROTOCOL.conf':b'SecAction "id:920350,phase:1,pass,log"\n'}

    def test_candidate_exact_exception_and_private_destinations(self):
        material=self.material();raw,used=p.isolated_config(material,'/tmp/private/candidate',True)
        self.assertIn(material[p.EXCEPTION],raw)
        self.assertEqual(used.count(p.EXCEPTION),1)
        self.assertNotIn(b'/var/log/modsecurity',raw)
        self.assertIn(b'SecAuditLog /tmp/private/candidate/run/audit.json',raw)

    def test_baseline_excludes_only_exception(self):
        material=self.material();before,_=p.isolated_config(material,'/tmp/private/arm',False)
        after,_=p.isolated_config(material,'/tmp/private/arm',True)
        self.assertEqual(after.replace(material[p.EXCEPTION],b'',1),before)

    def test_pointer_must_exist_once(self):
        for value in (b'',(p.POINTER+'\n') .encode()*2):
            material=self.material();material[p.ROOT+'/modsecurity-override.conf']=value
            with self.assertRaises(p.safe.Refused):p.isolated_config(material,'/tmp/private/arm',True)

    def test_extra_operating_include_refused(self):
        material=self.material();material[p.ROOT+'/setup.conf']+=b'Include /var/log/modsecurity/capstone-managed/audit-path.conf\n'
        with self.assertRaises(p.safe.Refused):p.isolated_config(material,'/tmp/private/arm',True)

    def test_include_cycle_refused(self):
        material=self.material();material[p.CRS+'/crs-setup.conf']=('Include '+p.ROOT+'/setup.conf\n').encode()
        with self.assertRaises(p.safe.Refused):p.isolated_config(material,'/tmp/private/arm',True)

    def test_comment_operating_path_is_not_active_configuration(self):
        material=self.material();material[p.ROOT+'/modsecurity.conf']+=b'  # Old example /var/log/modsecurity/audit.log\n'
        raw,_=p.isolated_config(material,'/tmp/private/arm',True)
        self.assertIn(b'# Old example /var/log/modsecurity/audit.log',raw)

    def test_active_operating_path_still_refused(self):
        material=self.material();material[p.ROOT+'/modsecurity.conf']+=b'SecGuardianLog /var/log/modsecurity/guardian.log\n'
        with self.assertRaises(p.safe.Refused):p.isolated_config(material,'/tmp/private/arm',True)

    def test_include_nonstandard_syntax_refused(self):
        material=self.material();material[p.ROOT+'/setup.conf']+=b'Include "outside.conf"\n'
        with self.assertRaises(p.safe.Refused):p.isolated_config(material,'/tmp/private/arm',True)

    def test_existing42_oracle(self):
        self.assertEqual(p.oracle(self.rows())['native_requests'],42)

    def rows(self):return json.loads((HERE.parent/'validation.json').read_bytes())['cases']

    def test_duplicate_missing_case_refused(self):
        rows=self.rows();rows[-1]=copy.deepcopy(rows[-2])
        with self.assertRaises(p.safe.Refused):p.oracle(rows)

    def test_negative_suppressed_refused(self):
        rows=self.rows();row=next(x for x in rows if x['phase']=='candidate' and x['mode']=='must_remain');row['rule_ids']=[]
        with self.assertRaises(p.safe.Refused):p.oracle(rows)

    def test_xss_removed_refused(self):
        rows=self.rows();row=next(x for x in rows if x['phase']=='candidate' and x['mode']=='xss');row['rule_ids'].remove(10300)
        with self.assertRaises(p.safe.Refused):p.oracle(rows)

    def test_positive_target_retained_refused(self):
        rows=self.rows();row=next(x for x in rows if x['phase']=='candidate' and x['mode']=='exception');row['rule_ids']=[row['target_rule']]
        with self.assertRaises(p.safe.Refused):p.oracle(rows)

    def test_exact_native_cases_unchanged(self):
        cases=p.old.cases()
        self.assertEqual(len(cases),21)
        self.assertEqual(sum(c['mode']=='exception' for c in cases),2)
        self.assertEqual(sum(c['mode']=='must_remain' for c in cases),17)
        self.assertEqual(sum(c['mode']=='xss' for c in cases),2)
        self.assertTrue(all(c['source'] in p.ADDRESSES and c['destination'] in p.ADDRESSES for c in cases))


if __name__=='__main__':unittest.main()
