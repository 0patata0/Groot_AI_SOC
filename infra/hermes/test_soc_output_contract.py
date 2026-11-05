import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import output_contract
import chat_contract


class OutputSkill(unittest.TestCase):
    def test_controller_failure_paths_render_the_same_table_without_claiming_actions(self):
        for detail in ('model_outer_timeout','model_subprocess_timeout_requires_review',
                       'model_tool_failure_requires_review','silent_model_result_requires_review'):
            text=output_contract.incident_failure(detail)
            self.assertIn('\n\n| 확인 항목 | 현재 결과 | 다음 조치·범위 |\n',text)
            self.assertEqual(sum(line.startswith('|') for line in text.splitlines()),6)
            self.assertIn('실행·승인·차단 결과를 확인할 수 없음',text)
            self.assertIn('알림 재전송은 조사·조치를 재실행하지 않음',text)
            self.assertNotIn('```',text)

    def test_unknown_failure_details_are_not_echoed_into_channel_or_table_cells(self):
        text=output_contract.incident_failure('secret|outside\nprivate-details')
        self.assertNotIn('secret',text);self.assertNotIn('private-details',text)
        self.assertIn('diagnostic_run_incomplete',text)

    def test_incident_and_verification_failure_reuse_one_table_policy(self):
        policy=output_contract.policy()
        self.assertIn('LLM 사건관리·자동 조사·재검토',policy)
        self.assertIn('검증 실패 보고',policy)
        self.assertIn('원문 JSON·제어 필드 설명·중복 시각 목록',policy)
        self.assertEqual(policy.count('SOC_OUTPUT_CONTRACT_V1'),1)

    def test_native_and_sdk_use_one_output_skill_and_keep_user_history(self):
        original=[{'role':'system','content':chat_contract.system_prompt(agent_role='hermes')},
                  {'role':'user','content':'이전 표를 유지하고 WAF 룰을 보여줘'}]
        before=copy.deepcopy(original)
        for role in ('hermes','ollama'):
            rows=chat_contract.project_messages(original,agent_role=role)
            text='\n'.join(r['content'] for r in rows if r['role']=='system')
            self.assertEqual(text.count('SOC_OUTPUT_CONTRACT_V1'),1)
            self.assertEqual(text.count('SOC_ROLE_CONTRACT_V1'),1)
            self.assertEqual(rows[-1],original[-1])
            self.assertIn('SOC_ACTIVE_ROLE: '+role,text)
        self.assertEqual(original,before)
        self.assertNotIn('name: soc-output',output_contract.policy())

    def test_installed_flat_skill_and_canonical_skill_are_identical(self):
        source=Path(__file__).parent/'skills/soc-output/SKILL.md'
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            with self.assertRaises(ValueError):output_contract.policy(base)
            (base/'SKILL.md').write_bytes(source.read_bytes())
            self.assertEqual(output_contract.policy(base),output_contract.policy())
            nested=base/'skills/soc-output';nested.mkdir(parents=True)
            (nested/'SKILL.md').write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError,'ambiguous'):output_contract.policy(base)

    def test_malformed_skill_cannot_silently_drop_format_or_authority_boundary(self):
        raw=(Path(__file__).parent/'skills/soc-output/SKILL.md').read_bytes()
        for invalid in (raw+raw,raw.replace(b'SOC_OUTPUT_CONTRACT_V1',b'',1),raw+b'\nextra',b'\xff',b''):
            with self.subTest(size=len(invalid)),self.assertRaises((ValueError,UnicodeError)):
                output_contract.policy_text(invalid)

    def test_lookup_projection_removes_actuator_guidance_but_preserves_roles_and_read_boundary(self):
        full=chat_contract.system_prompt(agent_role='hermes')
        readonly=chat_contract.system_prompt(read_only=True,agent_role='hermes')
        self.assertLess(len(readonly),len(full))
        self.assertNotIn('edit_anchors',readonly)
        self.assertNotIn('<!-- bounded-operations-policy:start -->',readonly)
        self.assertIn('SOC_ROLE_CONTRACT_V1',readonly)
        self.assertIn('SOC_OUTPUT_CONTRACT_V1',readonly)
        self.assertIn(chat_contract.READ_COMPLETION_GUIDANCE,readonly)
        self.assertIn('edit_anchors',full)
        original={'model':'qwen3.6:35b','messages':[{'role':'system','content':'Native'}],
                  'extra_body':{'reasoning_effort':'high','think':True}}
        projected=chat_contract.normalize_openai(original,read_only=True,agent_role='hermes')
        self.assertEqual(projected['reasoning_effort'],'none')
        self.assertNotIn('think',projected.get('extra_body',{}))
        self.assertEqual(original['extra_body']['reasoning_effort'],'high')
