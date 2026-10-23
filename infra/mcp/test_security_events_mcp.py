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
                         {"search_suricata_alerts", "search_modsecurity_alerts"})
        self.assertTrue(lines[2]["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
