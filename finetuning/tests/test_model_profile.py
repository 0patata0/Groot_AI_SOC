"""No GPU or package installation: test model boundaries and failure cases."""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import model_profile as profile
from audit_tools import audit_rows


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / 'config.qwen36-thor.json').read_text())

    def test_legacy_profile_preserved_and_loader_not_confused(self):
        old = json.loads((ROOT / 'config.json').read_text())
        self.assertEqual(old['model_name_or_path'], 'Qwen/Qwen3-30B-A3B')
        self.assertEqual(profile.validate_profile(old), 'causal_lm')
        a, b = object(), object()
        with patch.dict(sys.modules, transformers=SimpleNamespace(AutoModelForCausalLM=a, Qwen3_5MoeForConditionalGeneration=b)):
            self.assertIs(profile.model_class(old), a)
            self.assertIs(profile.model_class(self.config), b)

    def test_wrong_architecture_unpinned_revision_and_untested_nf4_rejected(self):
        for changes in ({'revision':'main'}, {'quantization':'nf4'}, {'target_modules':['q_proj']}, {'min_available_memory_gib':20}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                profile.validate_profile({**self.config, **changes})
        with self.assertRaises(ValueError):
            profile.validate_model_config(self.config, SimpleNamespace(model_type='qwen3_moe', architectures=['Qwen3MoeForCausalLM']))

    def test_language_attention_coverage_includes_delta_and_excludes_vision_experts(self):
        names=[]
        for i in range(40):
            group, projections = ('self_attn',['q_proj','k_proj','v_proj','o_proj']) if i%4==3 else ('linear_attn',['in_proj_qkv','in_proj_z','in_proj_b','in_proj_a','out_proj'])
            names.extend((f'model.language_model.layers.{i}.{group}.{p}',None) for p in projections)
        names += [('model.visual.blocks.0.attn.q_proj',None),('model.language_model.layers.0.mlp.experts.gate_up_proj',None)]
        result=profile.check_lora_targets(self.config,names)
        self.assertEqual(len(result['modules']),190)
        with self.assertRaises(ValueError): profile.check_lora_targets(self.config,names[1:])

    def test_unexpected_trainable_vision_or_base_weight_rejected(self):
        allowed=('base_model.model.model.language_model.layers.0.linear_attn.in_proj_qkv.lora_A.default.weight',SimpleNamespace(requires_grad=True))
        profile.check_trainable_scope(self.config,[allowed])
        for name in ['model.visual.q_proj.lora_A.weight','base_model.model.model.language_model.layers.0.mlp.weight']:
            with self.assertRaises(ValueError):profile.check_trainable_scope(self.config,[allowed,(name,SimpleNamespace(requires_grad=True))])

    def test_current_free_memory_and_wrong_hardware_do_not_start_training(self):
        good={'bf16_supported':True,'platform':'aarch64','compute_capability':[11,0],'available_memory_gib':100}
        profile.check_training_capacity(self.config,good)
        for override in ({'available_memory_gib':78.65},{'available_memory_gib':None},{'compute_capability':[12,1]},{'bf16_supported':False}):
            with self.assertRaises(RuntimeError):profile.check_training_capacity(self.config,{**good,**override})


class ToolAuditTests(unittest.TestCase):
    def setUp(self):
        self.catalog={'tools':[{'name':'mcp__wazuh_ro__get_wazuh_agents','protected':False,'parameters':{'type':'object','properties':{'status':{'type':'string','enum':['active']}},'required':['status'],'additionalProperties':False}}]}

    def row(self,name,args):
        return {'messages':[{'role':'assistant','tool_calls':[{'function':{'name':name,'arguments':args}}]}]}

    def test_public_names_are_not_automatically_translated(self):
        result=audit_rows([self.row('get_agents',{})],self.catalog)
        self.assertEqual(result['counts']['unknown_tool_calls'],1)
        self.assertFalse(result['policy_and_answer_accuracy_reviewed'])

    def test_missing_required_wrong_type_and_unhandled_schema_are_not_validated(self):
        name=self.catalog['tools'][0]['name']
        rows=[self.row(name,{}),self.row(name,{'status':True}),self.row(name,{'status':'active'})]
        result=audit_rows(rows,self.catalog)
        self.assertEqual(result['counts']['schema_valid_calls'],1)
        modified=copy.deepcopy(self.catalog);modified['tools'][0]['parameters']['properties']['status']['format']='special'
        self.assertEqual(audit_rows(rows[-1:],modified)['counts']['invalid_or_unchecked_calls'],1)

    def test_protected_call_schema_is_not_policy_approval(self):
        self.catalog['tools'][0]['protected']=True
        result=audit_rows([self.row(self.catalog['tools'][0]['name'],{'status':'active'})],self.catalog)
        self.assertEqual(result['counts']['protected_named_calls_requiring_policy_review'],1)
        self.assertFalse(result['policy_and_answer_accuracy_reviewed'])


if __name__ == '__main__': unittest.main()
