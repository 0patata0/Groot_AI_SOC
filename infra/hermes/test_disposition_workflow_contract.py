"""Complete judgment guidance and the actual one-shot repair profile."""
import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import soc_management_run as gate
import workflow_contract
import test_soc_management_grounding as grounding_fixtures

READ = 'mcp__wazuh_ro__get_wazuh_alert_summary'
MODEL = 'soc-qwen36:35b-balanced-q4km-20261108'


def fixture(draft):
    h = grounding_fixtures.Grounding(); h.setUp(); h.completed.append(READ)
    h.kw['assistant_message'].content = draft
    h.agent.model = MODEL
    h.agent.base_url = 'http://10.200.10.10:11435/v1'
    request = dict(h.request, model=MODEL, max_tokens=6144)
    h.agent._build_api_kwargs = lambda: gate.management_reasoning(copy.deepcopy(request), h.agent)
    callback = gate.grounding_wrapper(lambda agent, **kw: 'original',
        types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
        lambda rows, row: rows.append(row), lambda rows, user: 0,
        h.completed, successful_reads={READ})
    return h, callback


class DispositionWorkflowContract(unittest.TestCase):
    def test_focused_and_installer_flat_copy_expose_the_same_complete_contract(self):
        focused = workflow_contract.section_policy(('soc-investigate',), 'incident-disposition')
        for required in ('assessment, basis, evidence_tools', '20~2000', '1~16',
                         'basis 필드를 생략하지 않는다', '실제 성공',
                         '판단을 정상·해결로 바꾸지 않는다'):
            self.assertIn(required, focused)
        self.assertNotIn('## 교차 검토 대조', focused)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'skill-soc-investigate.md').write_bytes(
                (Path(workflow_contract.__file__).parent / 'skills/soc-investigate/SKILL.md').read_bytes())
            self.assertEqual(workflow_contract.section_policy(
                ('soc-investigate',), 'incident-disposition', root), focused)

    def test_control_format_rule_has_one_canonical_home(self):
        full = workflow_contract.policy(('soc-investigate',))
        self.assertEqual(full.count('두 제어 줄이 모두 필요하면'), 1)
        self.assertEqual(full.count('판단 메타데이터 형식\n'), 1)

    def test_missing_judgment_repair_receives_complete_shared_fields(self):
        h, callback = fixture('반환 표본을 확인했습니다.\nMANAGEMENT_STATUS: resolved')
        with patch.dict(os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify',
                 'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED': '1'}, clear=True):
            self.assertEqual(callback(h.agent, **h.kw).action, 'continue')
        nudge = h.kw['messages'][-1]['content']
        self.assertEqual(nudge.count('## 판단 메타데이터 형식'), 1)
        self.assertIn('assessment, basis, evidence_tools', nudge)
        self.assertIn('basis 필드를 생략하지 않는다', nudge)
        self.assertNotIn('assessment는 benign/remediated/unresolved 중 하나', nudge)

    def test_new_judgment_keeps_normal_reasoning_and_does_not_force_a_verdict(self):
        h, callback = fixture('반환 표본을 확인했습니다.\nMANAGEMENT_STATUS: resolved')
        with patch.dict(os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify',
                 'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED': '1'}, clear=True):
            self.assertEqual(callback(h.agent, **h.kw).action, 'continue')
            request = h.agent._build_api_kwargs()
            self.assertEqual(request['reasoning_effort'], 'medium')
            self.assertEqual(request['max_tokens'], 6144)
            self.assertEqual(request['tool_choice'], 'auto')
            self.assertNotIn('incident_disposition_missing', gate.LITERAL_REPAIR_ISSUES)

    def test_existing_valid_judgment_conflict_uses_one_shot_literal_profile(self):
        decision = {'assessment': 'unresolved',
            'basis': '조회된 표본의 한계를 확인했지만 전체 영향과 현재 위험 해소는 미확인입니다.',
            'evidence_tools': [READ]}
        draft = ('판단 근거는 반환 표본이며 전체 영향은 미확인입니다.\nINCIDENT_DISPOSITION: ' +
                 json.dumps(decision, ensure_ascii=False) + '\nMANAGEMENT_STATUS: resolved')
        h, callback = fixture(draft)
        with patch.dict(os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify',
                 'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED': '1'}, clear=True):
            self.assertEqual(callback(h.agent, **h.kw).action, 'continue')
            request = h.agent._build_api_kwargs()
            self.assertEqual((request['reasoning_effort'], request['max_tokens']), ('none', 2048))
            self.assertEqual(request['tool_choice'], 'auto')
            restored = h.agent._build_api_kwargs()
            self.assertEqual((restored['reasoning_effort'], restored['max_tokens']), ('medium', 6144))
        self.assertEqual(h.kw['assistant_message'].content, draft)
        self.assertIn('판단을 정상·해결로 바꾸지 않는다', h.kw['messages'][-1]['content'])
        self.assertEqual(h.completed, [READ])


if __name__ == '__main__':
    unittest.main()
