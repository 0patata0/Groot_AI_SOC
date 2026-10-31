import contextlib
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import security_rule_inventory as inv
import rule_change_executor as parser
import rule_change_mcp as mcp


def api_items():
    def row(rid, details, custom=False, disabled=False):
        return {'id':rid, 'level':10, 'relative_dirname':'etc/rules' if custom else 'ruleset/rules',
                'filename':'local_rules.xml' if custom else 'base.xml', 'status':'disabled' if disabled else 'enabled',
                'details':details, 'groups':['auth'], 'mitre':['T1110'], 'description':'fixture'}
    return [row(5710, {}), row(5712, {'frequency':'8', 'timeframe':'120', 'if_matched_sid':'5710', 'same_source_ip':''}),
            row(12, {}, disabled=True), row(100001, {'if_sid':'5710', 'if_group':'missing',
                 'same_field':'user.name', 'different_field':'host.name'}, custom=True)]


def archive(contents):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w') as tar:
        for name,data in contents.items():
            info=tarfile.TarInfo(name.lstrip('/'));info.size=len(data);tar.addfile(info,io.BytesIO(data))
    return raw.getvalue()


class FakeEngine:
    def __init__(self):
        self.runner=SimpleNamespace(call=lambda argv:json.dumps([{'Id':'a'*64,'State':{'StartedAt':'2026-10-31T00:00:00Z'}}]).encode())
    def spec(self,target):
        if target!='b:wazuh-local-rules':raise ValueError('wrong_host')
        return {'container':'fixed-manager'}
    def locked(self):return contextlib.nullcontext()
    def _inspect(self,spec):return {'running':True}


class Inventory(unittest.TestCase):
    def collect(self,request=None,contents=None):
        return inv.inventory(FakeEngine(),parser,{'target':'b:wazuh',**(request or {})},api_reader=lambda:contents if contents is not None else api_items())

    def test_full_definitions_include_builtin_custom_and_excluded(self):
        d=self.collect();self.assertEqual(d['status'],'complete')
        self.assertEqual((d['counts']['builtin'],d['counts']['custom'],d['counts']['excluded']),(3,1,1))
        self.assertEqual(d['counts']['configured'],3);self.assertFalse(d['runtime_load_verified'])
        self.assertEqual(d['receipt_sha256'],inv.digest({k:v for k,v in d.items() if k!='receipt_sha256'}))

    def test_correlation_keeps_conditions_dependencies_and_namespace(self):
        d=self.collect({'correlation_only':True,'view':'details'})
        self.assertEqual(d['matched_count'],2)
        rule=next(r for r in d['rules'] if r['id']=='5712')
        self.assertEqual(rule['attributes']['frequency'],'8');self.assertEqual(rule['attributes']['timeframe'],'120')
        self.assertEqual(rule['references'][0]['value'],'5710');self.assertTrue(rule['references'][0]['configured_definition_found'])
        self.assertEqual(rule['mitre'],['T1110'])
        local=next(r for r in d['rules'] if r['id']=='100001')
        self.assertFalse(local['references'][1]['definition_found'])
        self.assertEqual([c['value'] for c in local['conditions'][-2:]],['user.name','host.name'])

    def test_snapshot_pagination_covers_every_row_and_refuses_drift(self):
        first=self.collect({'view':'details','limit':2})
        second=self.collect({'view':'details','limit':2,'offset':2,'snapshot_id':first['snapshot_id']})
        self.assertEqual(first['next_offset'],2);self.assertIsNone(second['next_offset'])
        self.assertEqual(len(first['rules']+second['rules']),4)
        with self.assertRaisesRegex(ValueError,'snapshot_changed'):self.collect({'offset':2,'snapshot_id':'0'*64})
        with self.assertRaises(ValueError):self.collect({'offset':2})

    def test_api_details_preserved_including_repeated_dynamic_fields(self):
        items=api_items();items[1]['details']['field']=[{'name':'user','value':'alice'},{'name':'host','value':'sensor'}]
        d=self.collect({'rule_id':'5712','view':'details'},items)
        self.assertEqual(d['rules'][0]['api_definition'],items[1])
        self.assertEqual(d['rules'][0]['details']['field'],items[1]['details']['field'])
        self.assertEqual(d['runtime']['definition_source'],'official_wazuh_API_rules')

    def test_api_invalid_schema_or_unavailable_never_means_empty(self):
        for value in ('unrecognised',None):
            items=api_items();items[0]['status']=value
            with self.assertRaises(ValueError):self.collect(contents=items)
        def failed():raise ValueError('API unavailable')
        with self.assertRaises(ValueError):inv.inventory(FakeEngine(),parser,{'target':'b:wazuh'},api_reader=failed)

    def test_waf_include_chain_builtin_custom_and_unread_gap(self):
        root=inv.WAF_ROOT
        files={root+'setup.conf':b'Include /etc/modsecurity.d/owasp-crs/rules/*.conf',
               root+'owasp-crs/rules/CRS.conf':b'SecRule ARGS "@rx attack" "id:942100,phase:2,chain"\nSecRule ARGS "@rx condition" "t:none"',
               root+'owasp-crs/rules/CAPSTONE.conf':b'SecAction "id:100001,phase:1,pass"'}
        rows,sources,warnings,removals=inv.waf_rules(files,parser)
        self.assertEqual(len(rows),2);self.assertFalse(warnings)
        self.assertEqual({r['origin'] for r in rows},{'builtin','custom'})
        self.assertIn('condition',rows[1]['definition'])
        files[root+'setup.conf']+=b'\nInclude /unread/custom.conf'
        self.assertTrue(inv.waf_rules(files,parser)[2])

    def test_waf_malformed_rule_is_a_visible_coverage_gap(self):
        files={inv.WAF_ROOT+'setup.conf':b'SecRule ARGS "@rx a" "phase:2,deny"'}
        self.assertTrue(inv.waf_rules(files,parser)[2])

    def test_suricata_pcre_quote_and_option_hyphen_preserve_sid(self):
        raw=b'''alert tcp any any -> any any (msg:"quoted sid:999;"; app-layer-protocol:!http; pcre:"/^["']?post/Ri"; sid:42; rev:2;)'''
        rows=inv.suricata_rules(raw,'fixed.rules','builtin',parser)
        self.assertEqual(rows[0]['id'],'42');self.assertIn('sid:999;',rows[0]['attributes']['msg'])
        with self.assertRaises(ValueError):inv.suricata_options(b'alert tcp any any -> any any (msg:"unterminated; sid:4;)')

    def test_archive_refuses_traversal_symlink_and_duplicate(self):
        for name,kind in [('../secret',tarfile.REGTYPE),('var/ossec/etc/rules/link',tarfile.SYMTYPE)]:
            out=io.BytesIO()
            with tarfile.open(fileobj=out,mode='w') as tar:
                member=tarfile.TarInfo(name);member.type=kind;member.linkname='/etc/shadow';tar.addfile(member)
            with self.assertRaises(ValueError):inv.archive_files(out.getvalue(),['/var/ossec/etc/rules'])

    def test_wrong_host_shell_path_and_unbounded_args_rejected(self):
        for request in ({'target':'a:waf'},{'command':'id'},{'limit':True},{'limit':101},{'offset':-1},
                        {'rule_id':'1; cat /etc/shadow'},{'target':[]},{'origin':'all;id'}):
            with self.subTest(request=request),self.assertRaises(ValueError):self.collect(request)

    def test_inconsistent_two_reads_refused(self):
        items=api_items();changed=api_items();changed[0]['level']=12
        replies=iter([items,changed])
        with self.assertRaisesRegex(ValueError,'changed_during_read'):
            inv.inventory(FakeEngine(),parser,{'target':'b:wazuh'},api_reader=lambda:next(replies))

    def test_new_tool_read_only_and_host_scoped(self):
        for host in ('a','b'):
            t=next(t for t in mcp.tool_list('read',host) if t['name']=='get_security_rules')
            self.assertTrue(all(x.startswith(host+':') for x in t['inputSchema']['properties']['target']['enum']))
            self.assertNotIn('get_security_rules',[t['name'] for t in mcp.tool_list('write',host)])

    def test_official_reader_uses_only_fixed_gets_and_existing_readonly_auth(self):
        env=b'WAZUH_API_HOST=127.0.0.1\nWAZUH_API_PORT=55000\nWAZUH_API_USERNAME=mcp-ro\nWAZUH_API_PASSWORD=fixture-password\nWAZUH_VERIFY_SSL=false\n'
        responses=iter([{'token':'fixture.token'}, {'affected_items':api_items(),'total_affected_items':4,'total_failed_items':0}])
        requests=[]
        class Opener:
            def open(self,request,timeout):
                requests.append((request.full_url,request.get_method()))
                return io.BytesIO(json.dumps({'error':0,'data':next(responses)}).encode())
        fake=SimpleNamespace(_read_regular=lambda path,limit:(env,SimpleNamespace(st_uid=0,st_mode=0o640)))
        with patch.object(inv.urllib.request,'build_opener',return_value=Opener()):
            self.assertEqual(inv.wazuh_api_reader(fake)(),api_items())
        self.assertEqual(requests,[('https://127.0.0.1:55000/security/user/authenticate','POST'),
                                  ('https://127.0.0.1:55000/rules?limit=5000&sort=id&offset=0','GET')])

    def test_credentials_host_identity_and_owner_changes_are_refused_before_http(self):
        base={'WAZUH_API_HOST':'127.0.0.1','WAZUH_API_PORT':'55000','WAZUH_API_USERNAME':'mcp-ro',
              'WAZUH_API_PASSWORD':'fixture-password','WAZUH_VERIFY_SSL':'false'}
        for key,value in [('WAZUH_API_HOST','example.invalid'),('WAZUH_API_USERNAME','admin'),('WAZUH_API_PORT','443')]:
            env={**base,key:value};raw='\n'.join(k+'='+v for k,v in env.items()).encode()
            fake=SimpleNamespace(_read_regular=lambda path,limit:(raw,SimpleNamespace(st_uid=0,st_mode=0o640)))
            with patch.object(inv.urllib.request,'build_opener') as network,self.assertRaises(ValueError):inv.wazuh_api_reader(fake)
            network.assert_not_called()


if __name__=='__main__':unittest.main()
