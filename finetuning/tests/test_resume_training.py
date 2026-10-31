import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import resume_training as resume
import dgx_supervisor as dgx


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.previous=self.root/'previous';self.previous.mkdir()
        self.checkpoint=self.previous/'checkpoint-136';self.checkpoint.mkdir()
        for name in resume.REQUIRED:(self.checkpoint/name).write_text('trusted fixture')
        (self.checkpoint/'trainer_state.json').write_text(json.dumps({'global_step':136,'max_steps':224}))
        self.base={'revision':'frozen','manifest_sha256':'a'*64}
        self.checks={'records':{'train':447,'validation':176,'test':176},'sha256':{'train':'a','validation':'b','test':'c'}}
        self.config={'learning_rate':5e-7,'seed':42,'output_dir':'original',
                     'training_deadline_epoch':1,'base_artifact_manifest':self.base}
        (self.previous/'run_manifest.json').write_text(json.dumps({'config':self.config,'data':self.checks,'base_artifact_manifest':self.base}))
        self.receipt=self.root/'receipt.json';self.receipt.write_text(json.dumps(resume.make_receipt(self.previous,self.checkpoint)))
        self.config={**self.config,'output_dir':'new','training_deadline_epoch':2,
                     'resume_from_checkpoint':str(self.checkpoint),'resume_manifest':str(self.receipt)}

    def test_new_output_and_deadline_preserve_optimizer_continuation_contract(self):
        self.assertEqual(resume.validate_resume(self.config,self.checks)['step'],136)

    def test_changed_adapter_optimizer_rng_or_provenance_rejected(self):
        for target in (self.checkpoint/'adapter_model.safetensors',self.checkpoint/'optimizer.pt',
                       self.checkpoint/'rng_state.pth',self.previous/'run_manifest.json'):
            old=target.read_bytes();target.write_bytes(old+b' ')
            with self.assertRaises(ValueError):resume.validate_resume(self.config,self.checks)
            target.write_bytes(old)

    def test_missing_optimizer_never_silently_restarts(self):
        (self.checkpoint/'optimizer.pt').unlink()
        with self.assertRaisesRegex(ValueError,'Incomplete'):resume.validate_resume(self.config,self.checks)

    def test_changed_learning_rate_seed_data_or_base_rejected(self):
        for change in ({'learning_rate':1e-4},{'seed':43},{'base_artifact_manifest':{'revision':'other'}}):
            with self.assertRaises(ValueError):resume.validate_resume({**self.config,**change},self.checks)
        for key,value in (('records',{'train':446}),('sha256',{'train':'different'})):
            with self.assertRaises(ValueError):resume.validate_resume(self.config,{**self.checks,key:value})

    def test_boolean_implicit_checkpoint_and_symlink_rejected(self):
        with self.assertRaises(ValueError):resume.validate_resume({**self.config,'resume_from_checkpoint':True},self.checks)
        link=self.root/'checkpoint-136';link.symlink_to(self.checkpoint,target_is_directory=True)
        with self.assertRaises(ValueError):resume.validate_resume({**self.config,'resume_from_checkpoint':str(link)},self.checks)

    def test_eta_uses_only_steps_executed_in_this_process(self):
        self.assertIsNone(resume.remaining_seconds(10,136,224,136))
        self.assertEqual(resume.remaining_seconds(20,137,224,136),1740)

    def test_loading_worker_detected_before_api_has_resident_model(self):
        proc=self.root/'proc';proc.mkdir();worker=proc/'12';worker.mkdir()
        (worker/'cmdline').write_bytes(b'/usr/local/lib/ollama/llama-server\0--model\0opaque\0')
        self.assertTrue(dgx.loading_inference_process(proc))
        with patch.object(dgx,'loading_inference_process',return_value=True),patch.object(dgx.urllib.request,'urlopen') as api:
            self.assertTrue(dgx.shared_model_active());api.assert_not_called()
        (worker/'cmdline').write_bytes(b'/usr/bin/python3\0a-llama-server-report.py\0')
        self.assertFalse(dgx.loading_inference_process(proc))
        (worker/'cmdline').write_bytes(b'/usr/local/bin/ollama\0runner\0')
        self.assertTrue(dgx.loading_inference_process(proc))

    def test_resume_mounts_cannot_write_the_original_checkpoint(self):
        c={'root':'/home/operator/Capstone_Groot_training/new','resume_parent':'/home/operator/Capstone_Groot_training/old',
           'run_id':'capstone-dgx-20261101-r1','uid':1000,'gid':1000,'image':'pinned'}
        args=dgx.docker_args(c,'main')
        self.assertIn('type=bind,src=/home/operator/Capstone_Groot_training/old/workspace/main,dst=/resume,readonly',args)
        self.assertIn('--network=none',args)
        self.assertNotIn('--gpus',dgx.docker_args(c,'resume-check'))


if __name__=='__main__':unittest.main()
