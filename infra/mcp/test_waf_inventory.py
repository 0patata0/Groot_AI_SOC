"""Rule semantics and native/parser disagreement must not silently disappear."""
import base64
import copy
import io
import json
import tarfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
import security_rule_inventory as I
import rule_change_executor as P

ROOT=I.WAF_ROOT


def files():
    return {ROOT+'setup.conf':('Include '+ROOT+'base.conf\nInclude '+ROOT+'rules.conf\n').encode(),
            ROOT+'base.conf':b'SecRuleEngine DetectionOnly\nSecDefaultAction "phase:2,pass,log"\n',
            ROOT+'rules.conf':b'''# comment
SecRule ARGS "@rx a,b" "id:42,phase:2,block,msg:'a,b',tag:'one',tag:'two',chain"
SecRule REQUEST_HEADERS:X "@rx next" "t:none,ctl:ruleRemoveById=99"
SecAction "id:43,phase:1,pass"
SecMarker END
SecRuleUpdateTargetById 42 "!ARGS:safe"
SecRuleRemoveById "40-42 99"
'''}


def nginx(extra=''):
    return ('# configuration file /etc/nginx/nginx.conf:\nhttp {\ninclude /etc/nginx/conf.d/*.conf;\n}\n'
            '# configuration file /etc/nginx/conf.d/modsecurity.conf:\n'
            'modsecurity on;\nmodsecurity_rules_file /etc/modsecurity.d/setup.conf;\n'+extra).encode()


def native(count=9,version='3.0.16',extra='',exit_code=0):
    return nginx(extra), ('ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 0/'+str(count)+'/0)\n'
        'libmodsecurity3 version '+version+'\nnginx: configuration file syntax is ok\nnginx: configuration file test is successful\n').encode(),exit_code


class WafSemantics(unittest.TestCase):
    def parsed(self,source=None):
        meta={};rows,sources,warnings,changes=I.waf_rules(source or files(),P,meta)
        return rows,sources,warnings,changes,meta

    def test_chain_actions_repeated_tags_and_commas_are_preserved(self):
        rows,_,warnings,changes,meta=self.parsed();self.assertEqual(warnings,[])
        first=rows[0]
        self.assertEqual(first['description'],'a,b');self.assertEqual(first['attributes']['tags'],['one','two'])
        self.assertEqual(first['conditions'][0]['operator'],'@rx a,b');self.assertEqual(first['chain_length'],2)
        self.assertEqual(first['conditions'][1]['variables'],'REQUEST_HEADERS:X')
        self.assertEqual(first['line'],2);self.assertEqual(first['conditions'][1]['line'],3)
        self.assertEqual(first['declared_disruptive_actions'],['block']);self.assertEqual(first['configured_base_action'],'pass')
        self.assertEqual(len(first['configuration_changes_by_id']),2)
        self.assertEqual(len(rows[1]['configuration_changes_by_id']),0)
        self.assertEqual(first['runtime_controls'][0]['control'],'ruleRemoveById=99')
        self.assertEqual(meta['engine_mode'],'DetectionOnly');self.assertEqual(meta['chain_continuations'],1)
        self.assertEqual(meta['native_expected_objects_3_0_16'],9)
        self.assertFalse(meta['per_request_effective_actions_verified'])

    def test_include_execution_order_and_per_phase_defaults(self):
        source=files();source[ROOT+'setup.conf']=('Include '+ROOT+'z.conf\nInclude '+ROOT+'a.conf\nInclude '+ROOT+'rules.conf').encode()
        source[ROOT+'z.conf']=b'SecRuleEngine On\nSecDefaultAction "phase:2,deny,status:403,log"'
        source[ROOT+'a.conf']=b'SecRuleEngine DetectionOnly\nSecDefaultAction "phase:1,pass,log"'
        rows,_,warnings,_,meta=self.parsed(source)
        self.assertEqual(warnings,[]);self.assertEqual(meta['engine_mode'],'DetectionOnly')
        self.assertEqual(rows[0]['configured_base_action'],'deny');self.assertEqual(rows[1]['configured_base_action'],'pass')
        self.assertEqual(rows[0]['default_actions']['source'],ROOT+'z.conf')

    def test_unselected_file_does_not_change_engine_mode_or_inherit_defaults(self):
        source=files();source[ROOT+'not_included.conf']=b'SecRuleEngine Off\nSecAction "id:88,phase:2,block"'
        rows,_,_,_,meta=self.parsed(source);row=next(r for r in rows if r['id']=='88')
        self.assertEqual(meta['engine_mode'],'DetectionOnly');self.assertEqual(meta['id_definitions'],2)
        self.assertEqual(row['configuration'],'unselected');self.assertIsNone(row['default_actions']);self.assertIsNone(row['configured_base_action'])

    def test_line_numbers_survive_continuations(self):
        source=files();source[ROOT+'rules.conf']=b'# comment\n\nSecRule ARGS "@rx a" \\\n "id:42,phase:2,pass"\n'
        rows,_,warnings,_,_=self.parsed(source);self.assertFalse(warnings);self.assertEqual(rows[0]['line'],3)

    def test_repeated_include_cycle_outside_root_and_unknown_source_are_visible(self):
        for extra in ('Include '+ROOT+'rules.conf','Include '+ROOT+'setup.conf','Include /tmp/unread.conf','SecRuleScript /unread.lua "id:99,phase:1"'):
            source=files();source[ROOT+'setup.conf']+=extra.encode()+b'\n'
            self.assertTrue(self.parsed(source)[2],extra)

    def test_broken_chain_is_not_silently_counted_complete(self):
        for body in (b'SecRule ARGS "a" "id:42,chain"',
                     b'SecRule ARGS "a" "id:42,chain"\nSecMarker END',
                     b'SecRule ARGS "a" "id:42,chain"\nSecRule ARGS "b" "id:43"'):
            source=files();source[ROOT+'rules.conf']=body
            self.assertTrue(self.parsed(source)[2])

    def test_native_count_reconciles_markers_not_chain_children(self):
        meta=self.parsed()[-1];result,warnings=I.waf_native_result(*native(),meta)
        self.assertFalse(warnings);self.assertEqual(result['status'],'passed')
        self.assertTrue(result['object_count_reconciliation']['matched'])
        self.assertFalse(result['running_worker_rule_state_verified'])
        result,warnings=I.waf_native_result(*native(10),meta)
        self.assertFalse(result['object_count_reconciliation']['matched']);self.assertIn('native_waf_object_count_mismatch',warnings)

    def test_other_native_version_does_not_reuse_verified_marker_formula(self):
        result,_=I.waf_native_result(*native(version='3.0.99'),self.parsed()[-1])
        self.assertIsNone(result['object_count_reconciliation']['matched'])

    def test_native_failure_no_counts_and_multiple_contexts_do_not_mean_zero(self):
        meta=self.parsed()[-1]
        result,warnings=I.waf_native_result(nginx(),b'configuration test failed',1,meta)
        self.assertEqual(result['status'],'failed');self.assertTrue(warnings)
        before=native();result,warnings=I.waf_native_result(before[0],before[1]+before[1],0,meta)
        self.assertIn('native_waf_count_unavailable_or_multiple_contexts',warnings)

    def test_nginx_comments_and_quoted_fake_directives_are_not_configuration(self):
        extra='# modsecurity off;\nlog_format fake "modsecurity off;";\n'
        directives,warnings=I.nginx_security_directives(nginx(extra).decode())
        self.assertFalse(warnings);self.assertEqual(len(directives),2)
        self.assertEqual([d['value'] for d in directives if d['directive']=='modsecurity'],['on'])

    def test_nginx_overrides_are_reported_and_extra_rules_are_gaps(self):
        directives,warnings=I.nginx_security_directives(nginx('location /safe { modsecurity off; }').decode())
        self.assertFalse(warnings);self.assertEqual([d['value'] for d in directives if d['directive']=='modsecurity'],['on','off'])
        for extra in ("modsecurity_rules 'SecRuleEngine On';",'modsecurity_rules_remote secret https://example.invalid;',
                      'modsecurity_rules_file /unread/other.conf;'):
            directives,warnings=I.nginx_security_directives(nginx(extra).decode())
            self.assertTrue(warnings);self.assertNotIn('secret',json.dumps(directives))

    def test_native_certificate_warning_is_separate_from_rule_parser_failure(self):
        body,err,code=native();err+=b'"ssl_stapling" ignored, issuer certificate not found'
        result,warnings=I.waf_native_result(body,err,code,self.parsed()[-1])
        self.assertEqual(warnings,[]);self.assertEqual(result['warning_codes'],['ssl_stapling_issuer_missing'])


class WafCollection(unittest.TestCase):
    def collect(self,check=None,request=None):
        source=files();out=io.BytesIO()
        # These files are under a fixed archive root that is read by the actual collector.
        source={n.replace(ROOT+'base.conf',ROOT+'modsecurity.conf').replace(ROOT+'rules.conf',ROOT+'owasp-crs/rules/test.conf'):
                raw.replace(b'base.conf',b'modsecurity.conf').replace(b'Include /etc/modsecurity.d/rules.conf',b'Include /etc/modsecurity.d/owasp-crs/rules/test.conf') for n,raw in source.items()}
        with tarfile.open(fileobj=out,mode='w') as tar:
            for name,data in source.items():
                member=tarfile.TarInfo(name.lstrip('/'));member.size=len(data);tar.addfile(member,io.BytesIO(data))
        identity=json.dumps([{'Id':'fixed','State':{'StartedAt':'2026-10-31T00:00:00Z'}}]).encode()
        engine=SimpleNamespace(spec=lambda t:{'container':'waf'},locked=nullcontext,_inspect=lambda s:{},
                               runner=SimpleNamespace(call=lambda argv:identity))
        return I.inventory(engine,P,{'target':'a:waf',**(request or {})},command=lambda argv:out.getvalue(),native_check=check or (lambda argv:native()))

    def test_real_collection_enforces_native_counts_and_keeps_summary_bounded(self):
        result=self.collect();self.assertEqual(result['status'],'complete');self.assertEqual(result['counts']['definitions'],2)
        meta=result['runtime']['waf_configuration'];self.assertEqual(meta['marker_declarations'],1)
        self.assertNotIn('markers',meta);self.assertIn('omitted',meta['detail_collections_scope'])
        self.assertEqual(self.collect(check=lambda argv:native(99))['status'],'partial')

    def test_changed_nginx_configuration_rejects_mixed_snapshot(self):
        answers=iter((native(),native(extra='location /safe { modsecurity off; }')))
        with self.assertRaisesRegex(ValueError,'nginx_configuration_changed'):
            self.collect(check=lambda argv:next(answers))

    def test_nginx_dump_is_part_of_pagination_snapshot(self):
        first=self.collect(request={'limit':1,'view':'details'})
        with self.assertRaisesRegex(ValueError,'snapshot_changed'):
            self.collect(check=lambda argv:native(extra='location /safe { modsecurity off; }'),
                         request={'limit':1,'view':'details','offset':1,'snapshot_id':first['snapshot_id']})


if __name__=='__main__':unittest.main()
