import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import output_contract
import chat_contract


class OutputSkill(unittest.TestCase):
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
