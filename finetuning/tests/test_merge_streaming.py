"""Reject exports that could silently omit or misapply trained weights."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from merge_streaming import plan_lora


class ExportPlanTests(unittest.TestCase):
    def setUp(self):
        self.module='model.language_model.layers.0.self_attn.q_proj'
        self.keys=['base_model.model.'+self.module+'.lora_'+side+'.weight' for side in 'AB']
        self.index={self.module+'.weight':'part.safetensors','mtp.fc.weight':'part.safetensors'}
        self.config={'model_kind':'qwen3_5_moe','quantization':'none','target_modules':r'model\.language_model\.layers\.\d+\.self_attn\.q_proj','expected_lora_modules':{'self_attn':1}}
        self.peft={'peft_type':'LORA','bias':'none','target_modules':self.config['target_modules'],'r':16,'lora_alpha':32}

    def test_targets_are_exact_and_auxiliary_weights_remain_untouched(self):
        pairs,scale=plan_lora(self.keys,self.index,self.peft,self.config)
        self.assertEqual(set(pairs),{self.module+'.weight'})
        self.assertEqual(scale,2)

    def test_missing_pair_target_or_unexpected_saved_weight_is_rejected(self):
        for keys,index in [(self.keys[:1],self.index),(self.keys,{}),(self.keys+['extra.weight'],self.index)]:
            with self.assertRaises(ValueError):plan_lora(keys,index,self.peft,self.config)

    def test_advanced_adapters_and_mismatched_policy_cannot_use_vanilla_math(self):
        for change in [{'use_dora':True},{'fan_in_fan_out':True},{'rank_pattern':{'x':8}},
                       {'modules_to_save':['lm_head']},{'target_modules':'.*'},{'r':0}]:
            with self.assertRaises(ValueError):plan_lora(self.keys,self.index,{**self.peft,**change},self.config)


if __name__=='__main__':unittest.main()
