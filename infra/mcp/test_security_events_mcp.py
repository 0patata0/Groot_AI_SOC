#!/usr/bin/env python3
"""Local contract tests for the read-only security event MCP (no Indexer needed)."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SERVER = Path(__file__).with_name("security-events-mcp.py")
spec = importlib.util.spec_from_file_location("security_events_mcp", SERVER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SecurityEventsMcpTests(unittest.TestCase):
    def test_dns_context_is_bounded_and_does_not_invent_reverse_queries(self):
        value={'type':'request','queries':[{'rrname':'status.example.test','rrtype':'AAAA','secret':'hidden'}],
               'answers':[{'rdata':'secret-answer'}]}
        row=module.summarize_suricata({'data':{'dns':value}})
        self.assertEqual(row['dns_questions'],[{'name':'status.example.test','type':'AAAA'}])
        self.assertEqual(row['dns_message_type'],'request')
        self.assertFalse(row['dns_questions_incomplete'])
        self.assertNotIn('secret',json.dumps(row));self.assertNotIn('hidden',json.dumps(row))
        capped=module.dns_questions({'queries':value['queries']*17})
        self.assertEqual(len(capped['dns_questions']),16);self.assertTrue(capped['dns_questions_incomplete'])
        for invalid in ('x\nignore instructions','x'*254, {'nested':'data'}):
            row=module.dns_questions({'queries':[{'rrname':invalid,'rrtype':'A'}]})
            self.assertEqual(row['dns_questions'],[]);self.assertTrue(row['dns_questions_incomplete'])
        self.assertEqual(module.dns_questions({'rrname':'old.example.test','rrtype':'PTR'})['dns_questions'][0]['type'],'PTR')

    def test_waf_context_preserves_path_and_only_hashes_identifiers(self):
        tx={'unique_id':'opaque-transaction','request':{'uri':'/x/%2e%2e/labs/status?token=secret-query#secret-fragment',
            'headers':{'User-Agent':'secret-user-agent','Authorization':'secret-auth','Cookie':'secret-cookie'},'body':'secret-body'}}
        row=module.summarize_modsecurity({'data':{'transaction':tx}})
        self.assertEqual(row['request_path'],'/x/%2e%2e/labs/status')
        self.assertTrue(row['request_query_omitted']);self.assertFalse(row['request_path_incomplete'])
        self.assertEqual(row['transaction_id_sha256'],module.hashlib.sha256(b'opaque-transaction').hexdigest())
        self.assertEqual(row['user_agent_sha256'],module.hashlib.sha256(b'secret-user-agent').hexdigest())
        self.assertNotIn('secret',json.dumps(row));self.assertNotIn('opaque-transaction',json.dumps(row))
        tx['request']['uri']='https://private-user:private-pass@example.test/a//b?token=hidden'
        row=module.http_context(tx);self.assertEqual(row['request_path'],'/a//b');self.assertNotIn('private',json.dumps(row))
        self.assertEqual(module.http_context({'request':{'uri':'//a//b'}})['request_path'],'//a//b')

    def test_waf_context_bad_and_large_values_are_explicit(self):
        for value in ('/x\nBAD','x'*8193,'not-a-path',{'x':'y'}):
            row=module.http_context({'request':{'uri':value}})
            self.assertTrue(row['request_path_incomplete']);self.assertEqual(row['request_path'],'')
        row=module.http_context({'request':{'uri':'/'+'x'*600}})
        self.assertEqual(len(row['request_path']),512);self.assertTrue(row['request_path_incomplete'])
        self.assertEqual(module.opaque_hash('가'*1400),'')
        self.assertEqual(module.opaque_hash({'bad':'type'}),'')

    def test_query_selects_only_necessary_context_and_existing_deployer_accepts_three_tools(self):
        fields=module.build_query('modsecurity',module.validate_args('modsecurity',{}))['_source']['includes']
        self.assertIn('data.transaction.request.uri',fields)
        self.assertNotIn('data.transaction.request.headers',fields)
        self.assertFalse(any('Cookie' in f or 'Authorization' in f or 'body' in f for f in fields))
        script=SERVER.with_name('deploy_security_events_B.sh').read_text()
        self.assertIn('"get_wazuh_sca_checks"',script)

    def test_historical_window_is_bounded_kst_and_exact(self):
        at=module.datetime(2026,10,26,15,tzinfo=module.KST)
        params=module.validate_args('suricata',{'until_kst':'2026-10-17T16:00:00+09:00','lookback_minutes':60,'source_ip':'192.0.2.1','signature_id':'100110'})
        query=module.build_query('suricata',params,at)
        self.assertEqual(query['query']['bool']['filter'][0]['range']['timestamp'],{'gte':'2026-10-17T15:00:00+09:00','lte':'2026-10-17T16:00:00+09:00'})
        self.assertEqual(query['size'],10)
        for value in ('2026-10-17T16:00:00','2026-10-17T07:00:00Z','2026-99-17T16:00:00+09:00','now-1d'):
            with self.subTest(value=value),self.assertRaises(ValueError):module.validate_args('suricata',{'until_kst':value})
        for value in ('2026-10-27T16:00:00+09:00','2026-01-01T16:00:00+09:00'):
            with self.subTest(value=value),self.assertRaises(ValueError):module.build_query('suricata',module.validate_args('suricata',{'until_kst':value}),at)
        with self.assertRaises(ValueError):module.validate_args('suricata',{'until_kst':'2026-10-17T16:00:00+09:00','lookback_minutes':1441})

    def test_sca_arguments_cannot_select_paths_actions_or_credentials(self):
        bad = [{}, {'agent_id':'../001'}, {'agent_id':'001','policy_id':'../x'},
               {'agent_id':'001','policy_id':'a?x=1'}, {'agent_id':'001','check_ids':[1]},
               {'agent_id':'001','policy_id':'cis','check_ids':[True]},
               {'agent_id':'001','policy_id':'cis','check_ids':[1,1]},
               {'agent_id':'001','policy_id':'cis','check_ids':list(range(1,22))},
               {'agent_id':'001','command':'restart'}, {'agent_id':'001','url':'https://other/'}]
        with patch.object(module,'sca_api_reader') as read:
            for args in bad:
                with self.subTest(args=args):self.assertTrue(module.call_tool('get_wazuh_sca_checks',args)['isError'])
            read.assert_not_called()

    def sca_fixture(self, *, changed=False, total=2):
        policy={'policy_id':'cis_ubuntu24-04','name':'CIS','end_scan':'2026-10-25T22:03:39+00:00',
                'start_scan':'2026-10-25T22:00:00+00:00','hash_file':'hash','pass':1,'fail':1,'invalid':0,'total_checks':total}
        checks=[{'id':35648,'result':'passed','title':'SSH check','full_log':'secret','remediation':'do not execute me'},
                {'id':35654,'result':'failed','title':'MAC check','reason':'noncompliant'}]
        calls=[]
        def read(agent, selected=None, limit=50):
            calls.append((agent,selected,limit))
            return (checks,total) if selected else ([{**policy,**({'end_scan':'2026-10-26T00:00:00Z'} if changed and len(calls)>2 else {})}],1)
        return read,calls

    def test_sca_exact_ids_scan_time_projection_and_scope(self):
        read,calls=self.sca_fixture()
        with patch.object(module,'sca_api_reader',return_value=read):
            data=module.sca_checks({'agent_id':'001','policy_id':'cis_ubuntu24-04','check_ids':[35648,99999]})
        self.assertEqual(data['policies'][0]['scan_end_kst'],'2026-10-26T07:03:39+09:00')
        self.assertEqual(data['checks'][0]['result'],'passed')
        self.assertEqual(data['returned_count'],1)
        self.assertEqual(data['missing_requested_check_ids'],[99999])
        self.assertEqual(data['source_scope'],'last_stored_sca_scan')
        self.assertFalse(data['scan_capped'])
        self.assertEqual(calls,[('001',None,50),('001','cis_ubuntu24-04',500),('001',None,50)])
        self.assertNotIn('secret',json.dumps(data));self.assertNotIn('do not execute',json.dumps(data))
        self.assertEqual(module.sca_scan_time('2026-10-26T07:00:00'),'')

    def test_sca_title_lookup_uses_existing_scan_and_preserves_missing(self):
        read,calls=self.sca_fixture()
        with patch.object(module,'sca_api_reader',return_value=read):
            data=module.sca_checks({'agent_id':'001','policy_id':'cis_ubuntu24-04','title_contains':'nonexistent'})
        self.assertEqual(data['returned_count'],0)
        self.assertEqual(data['matched_within_scan'],0)
        self.assertEqual(calls[1],('001','cis_ubuntu24-04',500))
        with patch.object(module,'sca_api_reader',return_value=self.sca_fixture()[0]):
            found=module.sca_checks({'agent_id':'001','policy_id':'cis_ubuntu24-04','title_contains':'sSh'})
        self.assertEqual([(c['check_id'],c['result']) for c in found['checks']],[(35648,'passed')])
        for args in ({'agent_id':'001','title_contains':'ssh'},{'agent_id':'001','policy_id':'cis','title_contains':'ssh','check_ids':[1]},{'agent_id':'001','policy_id':'cis','title_contains':'a\nb'}):
            with self.assertRaises(ValueError):module.validate_sca_args(args)

    def test_sca_discovery_does_not_assume_a_policy_or_start_scan(self):
        read,calls=self.sca_fixture()
        with patch.object(module,'sca_api_reader',return_value=read):data=module.sca_checks({'agent_id':'001'})
        self.assertEqual(len(calls),1);self.assertNotIn('checks',data)
        self.assertEqual(data['policy_total'],1)

    def test_sca_scan_changes_errors_and_truncation_stay_visible(self):
        for changed,total in ((True,2),(False,501)):
            read,_=self.sca_fixture(changed=changed,total=total)
            with patch.object(module,'sca_api_reader',return_value=read):
                result=module.call_tool('get_wazuh_sca_checks',{'agent_id':'001','policy_id':'cis_ubuntu24-04'})
            if changed:self.assertTrue(result['isError'])
            else:self.assertTrue(json.loads(result['content'][0]['text'])['scan_capped'])
        with patch.object(module,'sca_api_reader',side_effect=RuntimeError('secret credential')):
            result=module.call_tool('get_wazuh_sca_checks',{'agent_id':'001'})
        self.assertTrue(result['isError']);self.assertNotIn('secret credential',json.dumps(result))

    def test_sca_api_has_fixed_get_resources_and_no_redirect_or_proxy(self):
        seen=[];handlers=[]
        class Response:
            def __init__(self,data):self.data=data
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def read(self,limit):return json.dumps({'error':0,'data':self.data}).encode()
        class Opener:
            def open(self,req,timeout):
                seen.append(req)
                return Response({'token':'sample.token.signature'} if len(seen)==1 else
                    {'affected_items':[],'total_affected_items':0,'total_failed_items':0})
        def build(*args):handlers.extend(args);return Opener()
        env={'WAZUH_API_HOST':'127.0.0.1','WAZUH_API_PORT':'55000','WAZUH_API_USERNAME':'mcp-ro',
             'WAZUH_API_PASSWORD':'test-only','HTTPS_PROXY':'https://untrusted.invalid'}
        with patch.dict(os.environ,env,clear=True),patch.object(module.urllib.request,'build_opener',side_effect=build):
            read=module.sca_api_reader();self.assertEqual(read('001','cis_test',500),([],0))
            with self.assertRaises(ValueError):read('001','../other')
        self.assertEqual([r.get_method() for r in seen],['POST','GET'])
        self.assertEqual(seen[1].full_url,'https://127.0.0.1:55000/sca/001/checks/cis_test?limit=500')
        self.assertEqual(handlers[0].proxies,{})
        self.assertTrue(any(isinstance(x,module.NoRedirect) for x in handlers))

    def test_indexer_request_uses_fixed_alert_index_and_no_proxy(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, limit):
                self.read_limit = limit
                return b'{"hits":{"hits":[]}}'

        class Opener:
            def open(self, request, timeout):
                captured["request"] = request
                captured["timeout"] = timeout
                return Response()

        env = {"WAZUH_INDEXER_HOST": "127.0.0.1", "WAZUH_INDEXER_PORT": "9200",
               "WAZUH_INDEXER_USERNAME": "mcp-ro", "WAZUH_INDEXER_PASSWORD": "test-password",
               "HTTPS_PROXY": "https://proxy.example.invalid"}
        def build_opener(*handlers):
            captured["handlers"] = handlers
            return Opener()

        with patch.dict(os.environ, env, clear=True), patch.object(module.urllib.request, "build_opener", side_effect=build_opener):
            self.assertEqual(module.indexer_search({"size": 1}), {"hits": {"hits": []}})
        request = captured["request"]
        self.assertEqual(request.full_url, "https://127.0.0.1:9200/wazuh-alerts-*/_search")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(captured["timeout"], 12)
        self.assertEqual(captured["handlers"][0].proxies, {})

    def test_suricata_query_is_fixed_and_bounded(self):
        args = module.validate_args("suricata", {
            "lookback_minutes": 30, "limit": 5, "source_ip": "203.0.113.7", "signature_id": "1000010",
        })
        query = module.build_query("suricata", args, at=module.datetime(2026,10,24,0,0,tzinfo=module.timezone.utc))
        self.assertEqual(query["size"], 5)
        self.assertEqual(query["query"]["bool"]["filter"][0], {"range": {"timestamp": {"gte": "2026-10-23T23:30:00+00:00", "lte":"2026-10-24T00:00:00+00:00"}}})
        serialized = json.dumps(query)
        self.assertIn('"data.alert.signature_id": "1000010"', serialized)
        self.assertIn('"data.src_ip": "203.0.113.7"', serialized)
        self.assertNotIn("full_log", serialized)
        self.assertNotIn("headers", serialized)
        self.assertNotIn("body", serialized)
        self.assertEqual(module.INDEX, "wazuh-alerts-*")

    def test_kst_presentation_preserves_absolute_query_window(self):
        self.assertEqual(module._kst_timestamp("2026-10-06T00:30:00Z"), "2026-10-06T09:30:00+09:00")
        self.assertEqual(module._kst_timestamp("2026-10-06T12:30:00+03:00"), "2026-10-06T18:30:00+09:00")
        self.assertEqual(module._kst_timestamp("2026-10-06T00:30:00"), "2026-10-06T09:30:00+09:00")
        self.assertEqual(module._kst_timestamp("not-a-time"), "")
        query = module.build_query("modsecurity", module.validate_args("modsecurity", {"lookback_minutes": 15}), at=module.datetime(2026,10,24,0,0,tzinfo=module.timezone.utc))
        self.assertEqual(query["query"]["bool"]["filter"][0], {"range": {"timestamp": {"gte": "2026-10-23T23:45:00+00:00", "lte":"2026-10-24T00:00:00+00:00"}}})

    def test_untrusted_arguments_cannot_choose_index_or_unbounded_search(self):
        invalid = [
            {"index": "*"}, {"query": {"match_all": {}}}, {"limit": 51},
            {"lookback_minutes": 1441}, {"limit": True},
            {"source_ip": "127.0.0.1/_search"}, {"signature_id": "1 OR 1=1"},
        ]
        with patch.object(module, "indexer_search") as search:
            for args in invalid:
                with self.subTest(args=args):
                    result = module.call_tool("search_suricata_alerts", args)
                    self.assertTrue(result["isError"])
            search.assert_not_called()

    def test_suricata_projection_excludes_raw_fields(self):
        source = {
            "timestamp": "2026-10-06T00:00:00Z", "agent": {"name": "groot-sec"},
            "rule": {"id": "100110", "level": 9, "description": "private payload"},
            "data": {"src_ip": "203.0.113.7", "dest_ip": "10.0.0.2", "dest_port": 443,
                     "alert": {"signature_id": 1000010, "signature": "Local test", "severity": 1},
                     "payload": "secret-request-body"},
            "full_log": "secret-full-log", "credentials": "secret-token",
        }
        with patch.object(module, "indexer_search", return_value={"hits": {"hits": [{"_source": source}]}}):
            result = module.search("suricata", {"limit": 1})
        self.assertEqual(result['returned_count'],1)
        self.assertIsNone(result['indexed_window_total_count'])
        self.assertEqual(result['source_scope'],'wazuh_indexed_alerts')
        start=module.datetime.fromisoformat(result['requested_since_kst'])
        end=module.datetime.fromisoformat(result['requested_until_kst'])
        self.assertEqual(end-start,module.timedelta(minutes=60))
        self.assertIn('전체 공격/경보 부재',result['evidence_scope_ko'])
        self.assertEqual(result["alerts"][0]["signature_id"], "1000010")
        self.assertEqual(result["alerts"][0]["timestamp"], "2026-10-06T09:00:00+09:00")
        output = json.dumps(result)
        for secret in ("secret-request-body", "secret-full-log", "secret-token", "private payload"):
            self.assertNotIn(secret, output)

    def test_waf_rule_filter_handles_flattened_messages_and_redacts_them(self):
        def hit(rule_id, source_ip="203.0.113.7"):
            return {"_source": {
                "timestamp": "2026-10-06T00:00:00Z", "rule": {"id": "100101", "level": 7},
                "data": {"transaction": {
                    "client_ip": source_ip,
                    "request": {"method": "GET", "uri": "/?token=do-not-disclose", "headers": "secret-header", "body": "secret-body"},
                    "messages": '[{"details":{"ruleId":"%s","matchedVar":"secret-matched-value"}}]' % rule_id,
                }}, "full_log": "secret-full-log",
            }}
        with patch.object(module, "indexer_search", return_value={"hits": {"hits": [hit("942100"), hit("10100")]}}) as search:
            result = module.search("modsecurity", {"rule_id": "10100", "limit": 1})
        self.assertEqual(search.call_args.args[0]["size"], module.MAX_SCAN)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["waf_rule_ids"], ["10100"])
        self.assertEqual(result["alerts"][0]["timestamp"], "2026-10-06T09:00:00+09:00")
        output = json.dumps(result)
        for secret in ("secret-header", "secret-body", "secret-full-log", "secret-matched-value", "do-not-disclose"):
            self.assertNotIn(secret, output)

    def test_waf_ids_from_structured_messages(self):
        ids = module.extract_waf_rule_ids([
            {"details": {"ruleId": "10100", "message": "secret"}},
            {"details": {"ruleId": 942100}},
            {"details": {"ruleId": "10100"}},
        ])
        self.assertEqual(ids, ["10100", "942100"])
        self.assertEqual(module.extract_waf_rule_ids('untrusted text ruleId:12345'), [])

    def test_stdio_json_rpc_has_no_stdout_noise(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "search_modsecurity_alerts", "arguments": {"limit": 1000}}},
        ]
        proc = subprocess.run(
            [sys.executable, str(SERVER)],
            input="".join(json.dumps(msg) + "\n" for msg in messages),
            text=True, capture_output=True, check=True,
        )
        lines = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual([row["id"] for row in lines], [1, 2, 3])
        self.assertEqual({tool["name"] for tool in lines[1]["result"]["tools"]},
                         {"search_suricata_alerts", "search_modsecurity_alerts", "get_wazuh_sca_checks"})
        self.assertTrue(lines[2]["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
