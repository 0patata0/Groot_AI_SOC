"""Trusted launch metadata enables read synthesis without granting authority."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import review_channel as review


class ReadActivation(unittest.TestCase):
    def test_review_read_workers_receive_only_fixed_activation_metadata(self):
        result = SimpleNamespace(stdout=json.dumps({'final_response': 'fixture'}).encode())
        for engine in ('ollama', 'hermes'):
            for readonly in (True, False, None, 'true'):
                with self.subTest(engine=engine, readonly=readonly), \
                        mock.patch.object(review.pwd, 'getpwnam', return_value=SimpleNamespace(
                            pw_name='fixture', pw_uid=995, pw_gid=986, pw_dir='/nonexistent')), \
                        mock.patch.object(review.os, 'getgrouplist', return_value=[986]), \
                        mock.patch.object(review.subprocess, 'run', return_value=result) as run:
                    job = {'id': 'a'*32, 'engine': engine, 'phase': 'lead',
                           'question': '현재 경보 조사해줘', 'readonly': readonly}
                    review.worker(job)
                    env = run.call_args.kwargs['env']
                    self.assertEqual(env.get('CAPSTONE_EVIDENCE_REPORT_COMPACT'),
                                     '1' if engine == 'ollama' and readonly is True else None)
                    self.assertFalse(run.call_args.kwargs.get('shell', False))
                    self.assertNotIn('CAPSTONE_MANAGEMENT_MODE', env)
                    self.assertNotIn('CAPSTONE_CHAT_READ_JSON', env)

    def test_installer_enables_sdk_read_path_without_general_permissions(self):
        import ast
        source = Path(__file__).resolve().parents[2] / 'deployment/ollama_trial_chat.py'
        node = next(n for n in ast.parse(source.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'service_text')
        namespace = {}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
        unit = namespace['service_text']()
        self.assertIn('Environment=CAPSTONE_EVIDENCE_REPORT_COMPACT=1\n', unit)
        for line in ('User=soc-ollama', 'NoNewPrivileges=yes', 'ProtectSystem=strict',
                     'PrivateDevices=yes', 'ReadWritePaths=/var/lib/capstone-ollama-trial/chat'):
            self.assertIn(line+'\n', unit)
        self.assertNotIn('CAPSTONE_MANAGEMENT_MODE=', unit)


if __name__ == '__main__':
    unittest.main()
