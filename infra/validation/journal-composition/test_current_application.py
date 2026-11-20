"""Replay pinned parent assertions with explicit current-contract replacements.

The parent sources remain unchanged. Each replaced assertion has a declared
reason and a stronger typed/negative check in current-application-contracts.json.
No runtime validator, tool dispatch or returned fixture evidence is patched.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('SOC_JOURNAL_COMPOSITION_ROOT', HERE.parents[2])).resolve()


def load(name, relative):
    path = ROOT / relative
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def adapted(group):
    registry = json.loads((HERE / 'current-application-contracts.json').read_text())
    item = registry['groups'][group]
    for relative, expected in item['parent_sha256'].items():
        path = ROOT / relative
        assert not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == expected, relative
    parent = load('current_contract_' + group.replace('-', '_'), item['entry'])
    if group == 'host-journal':
        parent = parent.m  # Retain the existing Linux-fd fixture adapter.

    if group == 'prior-claim':
        def first_scope(self):
            h = sys.modules['harness']
            question = 'WAF 최근 경보 조사해줘'
            unrelated = self.completed_sample()  # An actual Suricata receipt.
            waf = copy.deepcopy(unrelated)
            waf['name'] = 'search_modsecurity_alerts'
            data = json.loads(waf['result']);data['source'] = 'modsecurity'
            waf['result'] = json.dumps(data)
            waf['result_sha256'] = hashlib.sha256(waf['result'].encode()).hexdigest()
            tool = 'mcp__security_events__search_modsecurity_alerts'
            navigation = 'mcp__security_events__get_web_service_target'
            with patch.object(h, 'incident_evidence_gap', return_value=True):
                self.assertEqual(h.incident_selection_scope(question, [unrelated]), {tool})
                self.assertIn(navigation, h.incident_selection_scope(question, [waf]))
                self.assertIn(navigation, h.incident_selection_scope('WAF 경보와 systemd 상태를 조사해줘', []))
                with patch.object(h, 'card_evidence_gaps', return_value=['suricata']):
                    expected = {h.EVIDENCE.BUNDLE_TOOL, 'mcp__security_events__search_suricata_alerts'}
                    self.assertEqual(h.incident_selection_scope(question, [waf], reference={'kind': 'evidence'}), expected)
                    self.assertEqual(h.incident_selection_scope(question, [], reference={'kind': 'evidence'}), expected | {tool})
            self.assertIsNone(h.incident_selection_scope('WAF 규칙 목록 보여줘', []))
        parent.CommonContract.test_first_scope_keeps_reference_mixed_and_later_reads = first_scope

    elif group == 'common-new':
        def observations(self):
            h = parent.H
            call = parent.sealed('search_suricata_alerts', {'source': 'suricata', 'alerts': [], 'returned_count': 0})
            def body(receipts):
                prompt = h.incident_observation_prompt('DNS 경보 조사해', receipts)
                raw = prompt.split('<untrusted_tool_observations>\n', 1)[1].split('\n</untrusted_tool_observations>', 1)[0]
                return json.loads(raw)
            value = body([call]);alias = 'mcp__security_events__search_suricata_alerts'
            self.assertEqual([row['tool'] for row in value['observations']], [alias])
            self.assertEqual(value['current_successful_tools'], [alias])
            self.assertEqual(value['observations'][0]['result']['returned_count'], 0)
            forged = copy.deepcopy(call);forged['result_sha256'] = '0' * 64
            rejected = body([forged])
            self.assertEqual(rejected['observations'], [])
            self.assertEqual(rejected['current_successful_tools'], [])

        def section_contract(self):
            c = parent.H.CONTRACT
            evidence = c.workflow_policy(('soc-investigate',), section='investigation-evidence')
            disposition = c.workflow_policy(('soc-investigate',), section='incident-disposition')
            self.assertIn('조사 근거 확인과 인용', evidence)
            self.assertRegex(evidence, r'표본\s*0건[^\n]*(?:정상|부재)')
            self.assertIn('성공·실패·미실행', evidence)
            self.assertIn('evidence_tools', disposition)
            self.assertIn('unresolved', disposition)
            self.assertNotIn('교차 검토 단계에서만', evidence + disposition)

        def host_qualifiers(self):
            for target in ('a:waf', 'b:vector', 'c:lab-api', 'b:unknown', 'a:fw'):
                with self.subTest(target=target):
                    self.assertEqual(parent.H.READ.host_mentions(target), [(0, len(target), target[0])])
            for text in ('a:b', 'b:c', 'c:a'):
                with self.subTest(text=text):
                    self.assertEqual(parent.H.READ.host_mentions(text), [])
        parent.EvidenceContract.test_observation_prompt_exposes_exact_successful_tool_identity = observations
        parent.EvidenceContract.test_skills_load_through_the_shared_section_contract = section_contract
        parent.HostScope.test_logical_target_qualifiers_are_distinct_from_letter_ratios = host_qualifiers

    elif group == 'host-journal':
        def current_is_not_history(self):
            for question in ('systemd 오류 로그 봐줘', '시스템 로그 보여줘', 'D systemd 오류 로그 봐줘',
                             'A B systemd 오류 로그 봐줘', 'b:unknown 로그 봐줘'):
                with self.subTest(question=question):
                    self.assertIsNone(parent.c.service_history_plan(parent.catalog(), question, parent.AT))
            for host in 'ABC':
                with self.subTest(host=host):
                    plan = parent.c.service_history_plan(parent.catalog(), host + ' systemd 현재 상태 보여줘', parent.AT)
                    self.assertIs(plan['current_only'], True)
                    self.assertEqual(plan['requirements'], [{'tool': 'mcp__system_diagnostics__get_system_diagnostics',
                                                           'arguments': {'target': host.lower() + ':systemd'}}])
                    self.assertEqual(plan['units'], {host.lower() + ':systemd': None})
                    self.assertIsNone(plan['initial_history_window_minutes'])
        parent.FixedHost.test_ambiguity_unknown_host_and_current_only_do_not_invent_history = current_is_not_history

    elif group == 'new-errors':
        def record_identity(self):
            question, receipts = self.source()
            context = parent.P.context(question, receipts);before = copy.deepcopy(context)
            messages = parent.C.service_report_messages(context, {parent.DIAG: 'diagnostics'}, [parent.DIAG])
            body = json.loads(messages[1]['content'])
            projected = body['untrusted_completed_reads'][0]['data']['entries'][0]
            original = receipts[0]['data']['entries'][0]
            self.assertEqual(projected['record_sha256'], original['record_sha256'])
            for key in ('message_excerpt', 'at_kst', 'priority', 'source_units', 'source_transport', 'message_state'):
                self.assertEqual(projected[key], original[key])
            wire = json.dumps(messages, ensure_ascii=False)
            for key in ('message_sha256', 'excerpt_sha256'):
                self.assertNotIn(key, projected)
                self.assertNotIn(original[key], wire)
            self.assertEqual(context, before)
            self.assertEqual(context['untrusted_completed_reads'][0]['receipt_sha256'], receipts[0]['receipt_sha256'])
        parent.HostAndProjection.test_per_row_hashes_stay_in_original_audit_without_model_repetition = record_identity

    elif group == 'runtime-health':
        def registered_targets(self):
            self.assertEqual(parent.d.RUNTIME_TARGETS, parent.h.ROLE_TARGETS)
            self.assertEqual(len(parent.d.TARGETS), 43)
            self.assertIn('soc:coverage', parent.d.TARGETS)
            self.assertEqual(parent.d.PROFILES['siem']['b:certificate-monitor'], 'capstone-cert-monitor.service')
            mcp = load('current_runtime_target_schema', 'infra/mcp/system-diagnostics-mcp.py')
            mcp._library = parent.d
            schema = next(row['inputSchema'] for row in mcp.tools() if row['name'] == 'get_system_diagnostics')
            self.assertEqual(set(schema['properties']['target']['enum']), set(parent.d.TARGETS))
            self.assertNotIn('/etc/shadow', schema['properties']['target']['enum'])
        parent.RuntimeTests.test_catalog_has_no_arbitrary_paths_and_matches_validator = registered_targets

    elif group == 'new-typed':
        def current_short_lookup(self):
            report, calls, selections, closed = self.run_case(current_only=True)
            self.assertNotIn('error_type', report)
            self.assertEqual([arguments for name, arguments in calls if name == 'get_host_inventory'],
                             [parent.args('services'), parent.args('containers'), parent.args('services', 100)])
            self.assertEqual(report['exposed_tools'], [parent.DIAG])
            self.assertEqual(report['protected_calls'], 0)
            self.assertEqual(report['chat_posts'], 0)
            self.assertEqual(closed, [True])
            self.assertEqual(report['status'], 'partial')
            identity = report['service_identity_discovery']
            self.assertEqual(identity['pending'], [])
            self.assertTrue(identity['missing_units'])
            self.assertEqual({row['view']: row['returned_rows'] for row in identity['observations']},
                             {'services': 101, 'containers': 1})
            self.assertTrue(all(row['component_identity_verified'] is False for row in identity['observations']))
            self.assertIn('loaded systemd unit', report['final_response'])
            self.assertIn('Docker 컨테이너', report['final_response'])
            self.assertIn('기능 상태는 미확인', report['final_response'])
            self.assertIn('과거 실행 성공의 근거가 아닙니다', report['final_response'])
        parent.SDK.test_current_short_lookup_uses_deferred_registered_read_without_initial_exposure = current_short_lookup
    else:
        raise AssertionError('unknown current-contract replay group')
    return parent


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', default=os.environ.get('SOC_CURRENT_REPLAY_GROUP'),
                        choices=('prior-claim', 'common-new', 'host-journal', 'new-errors', 'runtime-health', 'new-typed'))
    args = parser.parse_args()
    assert args.group is not None
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(adapted(args.group)))
    raise SystemExit(0 if result.wasSuccessful() else 1)
