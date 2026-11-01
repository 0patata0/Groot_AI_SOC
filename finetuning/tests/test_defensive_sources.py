import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from collect_defensive_sources import arrival_review, safe_path, select_path, verify_blob, plan
from review_defensive_sources import crs_records, deduplicate, section_records, wazuh_records, xml_rules, history_review
from collect_incident_sources import validate_url, extract


class SourceReviewTests(unittest.TestCase):
    def test_reference_host_allowlist(self):
        validate_url('https://cert.cyber.gouv.fr/uploads/report.pdf')
        for url in ('http://www.cyber.gov.au/x','https://www.cyber.gov.au.evil.test/x','https://user:password@www.cyber.gov.au/x','https://127.0.0.1/x'):
            with self.subTest(url=url),self.assertRaises(ValueError):validate_url(url)

    def test_html_preserves_tables_without_executing_script(self):
        try:import lxml
        except ImportError:self.skipTest('Optional HTML extraction dependency unavailable')
        data=b'<html><body><main><h1>Incident</h1><h2>Evidence</h2><script>bad()</script><table><tr><td>observed</td></tr></table></main></body></html>'
        result=extract(data,'html');self.assertEqual(result['tables'],1)
        self.assertNotIn('bad()',result['text']);self.assertFalse(result['training_admitted'])

    def test_ambiguous_html_boundary_held(self):
        try:import lxml
        except ImportError:self.skipTest('Optional HTML extraction dependency unavailable')
        with self.assertRaises(ValueError):extract(b'<html><article>A</article><article>B</article></html>','html')

    def test_history_exact_match_and_file_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);old=home/'data-old';old.mkdir();new=home/'data-new';(new/'review').mkdir(parents=True)
            text='An example observable long enough to be checked exactly.'
            data=json.dumps({'messages':[{'content':text}]})+'\n'
            (old/'train.jsonl').write_text(data);(old/'copy.jsonl').write_text(data)
            (new/'review/regression-records.jsonl').write_text(json.dumps({'id':'case','input':{'log':text}})+'\n')
            result=history_review(new,home)
            self.assertEqual(result['unique_file_contents'],1);self.assertEqual(result['matched_record_ids'],['case'])

    def test_blob_integrity(self):
        data=b'example\n';item={'size':len(data),'sha':hashlib.sha1(b'blob 8\0'+data).hexdigest()}
        verify_blob(data,item)
        with self.assertRaises(ValueError):verify_blob(b'Example\n',item)
        with self.assertRaises(ValueError):verify_blob(data+b'!',item)

    def test_unsafe_paths(self):
        for path in ('../x','/x','a/../b','a\\b','a//b','a/./b',''):
            with self.subTest(path=path),self.assertRaises(ValueError):safe_path(path)
        self.assertEqual(str(safe_path('rules/a.conf')),'rules/a.conf')

    def test_yaml_does_not_execute(self):
        with self.assertRaises(Exception):arrival_review(b'!!python/object/apply:os.system ["false"]','x.yaml')
        self.assertFalse(arrival_review(b'# empty','x.yaml')['yaml_mapping'])

    def test_bound_selection(self):
        self.assertTrue(select_path('crs','tests/regression/tests/a/b.yaml'))
        self.assertFalse(select_path('crs','tests/run.sh'))
        self.assertFalse(select_path('suricata_verify','a/attack.pcap'))
        self.assertFalse(select_path('modsecurity_docs','CLAUDE.md'))

    def test_plan_rejects_untrusted_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'data-fixture';spec=Path(tmp)/'spec.json'
            spec.write_text(json.dumps({'source_pins':[{'id':'crs','repo':'other/repo','commit':'a'*40}]}))
            with self.assertRaises(ValueError):plan(root,spec)

    def test_truncated_tree_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'data-fixture';root.mkdir();spec=Path(tmp)/'spec.json'
            pin={'id':'crs','repo':'coreruleset/coreruleset','commit':'a'*40,'tree':'b'*40}
            spec.write_text(json.dumps({'source_pins':[pin]}))
            (root/'crs-commit.json').write_text(json.dumps({'sha':pin['commit'],'commit':{'tree':{'sha':pin['tree']}}}))
            (root/'crs-tree.json').write_text(json.dumps({'sha':pin['tree'],'truncated':True,'tree':[]}))
            with self.assertRaises(ValueError):plan(root,spec)

    def test_ini_preserves_duplicate_log_keys(self):
        rows=list(section_records('[one]\nrule= 12 \nalert= 3\ndecoder=\nlog 1 fail=a\nlog 1 fail=b\n'))
        self.assertEqual(rows[0][1]['rule'],'12');self.assertEqual(len(rows[0][2]),2)
        self.assertEqual(rows[0][1]['decoder'],'')

    def test_continuation_quarantined(self):
        row=next(wazuh_records('[a]\nrule=1\nalert=3\ndecoder=x\nlog 1 pass=a\n continuation\n','x.ini',{'1':[{'level':'3'}]}))
        self.assertIn('unsupported_continuation',row['reasons'])

    def test_negative_not_benign_and_empty_decoder_valid(self):
        row=next(wazuh_records('[a]\nrule=1\nalert=3\ndecoder=\nlog 1 fail=a\n','x.ini',{'1':[{'level':'3'}]}))
        self.assertEqual(row['target']['predicate'],'expected_tuple_does_not_match');self.assertFalse(row['reasons'])
        self.assertEqual(row['input'],{'log':'a'})

    def test_unknown_rule_held(self):
        row=next(wazuh_records('[a]\nrule=1\nalert=3\ndecoder=x\nlog 1 pass=a\n','x.ini',{}))
        self.assertIn('rule_definition_unresolved',row['reasons'])

    def test_xml_entities_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'a.xml').write_text('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
            index,errors=xml_rules(p);self.assertFalse(index);self.assertEqual(errors,['a.xml'])

    def crs(self,rule=1,positive=True):
        value={'rule_id':rule,'tests':[{'test_id':1,'stages':[{'input':{'uri':'/'},'output':{'log':{'expect_ids' if positive else 'no_expect_ids':[rule]}}}]}]}
        return next(crs_records(value,f'tests/family{rule}/a.yaml',{'1','2'}))

    def test_rule_query_scope_not_assertion_leak(self):
        row=self.crs();self.assertEqual(row['input']['fixture_rule_id'],1)
        self.assertNotIn('expect_ids',json.dumps(row['input']))

    def test_different_queries_not_conflicting_same_observation_reserved_together(self):
        rows=deduplicate([self.crs(1,True),self.crs(2,False)])
        self.assertTrue(all(not r['reasons'] for r in rows))
        self.assertEqual(rows[0]['split_group'],rows[1]['split_group'])

    def test_true_conflict_held(self):
        rows=deduplicate([self.crs(1,True),self.crs(1,False)])
        self.assertTrue(all('same_input_conflicting_assertions' in r['reasons'] for r in rows))

    def test_identical_duplicate_not_admitted(self):
        row=self.crs();other=copy.deepcopy(row);other['id']+='copy'
        rows=deduplicate([row,other]);self.assertEqual(sum(not r['reasons'] for r in rows),1)
        self.assertTrue(all(not r['training_admitted'] for r in rows))

    def test_multistage_kept_ordered(self):
        value={'rule_id':1,'tests':[{'stages':[{'input':{'uri':p},'output':{'status':s}} for p,s in [('/a',200),('/b',403)]]}]}
        row=next(crs_records(value,'tests/family/a.yaml',{'1'}))
        self.assertEqual([s['uri'] for s in row['input']['stages']],['/a','/b'])
        self.assertEqual(len(row['target']['stage_assertions']),2)

    def test_partition_balanced_without_splitting_family(self):
        rows=[]
        for family in range(5):
            for n in range(10):
                r=self.crs();r['family']=str(family);r['id']=f'{family}:{n}';r['input']['stages']=[{'uri':r['id']}];rows.append(r)
        rows=deduplicate(rows)
        self.assertEqual(sum(r['provisional_partition']=='reserved_evaluation' for r in rows),10)
        for f in range(5):self.assertEqual(len({r['provisional_partition'] for r in rows if r['family']==str(f)}),1)


if __name__=='__main__':unittest.main()
