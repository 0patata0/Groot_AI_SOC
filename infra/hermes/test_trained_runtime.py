"""Trained operator model keeps exact native read leases and authority bounds."""
import copy
import importlib.util
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_soc_management_selection import agent, request, NAME, DEPS
from test_soc_management_run import wrapper as w

TRAINED = 'soc-qwen36:35b-balanced-q4km-20261108'


class TrainedRuntime(unittest.TestCase):
    def test_identity_is_exact_and_request_cannot_switch_operator_model(self):
        for model in ('qwen3.6:35b', TRAINED):
            a = agent(); a.model = model
            self.assertTrue(w.verified_runtime_model(a, model))
            for other in (None, [], {}, 'unknown', model + '-copy',
                          TRAINED if model != TRAINED else 'qwen3.6:35b'):
                self.assertFalse(w.verified_runtime_model(a, other))

    def test_reasoning_profile_matches_base_without_changing_tools(self):
        with patch.dict(w.os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify'}, clear=True):
            a = agent(); r = request(); original = copy.deepcopy(r)
            base = w.management_reasoning(r, a, required_read_phase=True)
            a.model = TRAINED; r = dict(r, model=TRAINED)
            trained = w.management_reasoning(r, a, required_read_phase=True)
            self.assertEqual(trained, dict(base, model=TRAINED))
            self.assertEqual(base['tools'], original['tools'])
            self.assertEqual(r, dict(original, model=TRAINED))
            override = dict(r, extra_body={'model': 'qwen3.6:35b'})
            self.assertIs(w.management_reasoning(override, a), override)

    @unittest.skipUnless(DEPS, 'existing server dependencies required')
    def test_actual_response_identity_nonce_and_exact_read_remain_bound(self):
        from openai.types.chat import ChatCompletion
        a = agent(); a.model = TRAINED; r = dict(request(), model=TRAINED)
        with patch.dict(w.os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify'}, clear=True):
            wire = w.management_read_request(r, a, pending=True)
            lease = a._capstone_management_selection
            self.assertEqual(wire['model'], TRAINED)
            value = {'request_nonce': lease['nonce'], 'calls': [
                {'tool': NAME, 'arguments': {'request_id': 'a' * 32}}]}
            def response(model, content):
                return ChatCompletion(id='provider-result', object='chat.completion', created=1,
                    model=model, choices=[{'index': 0, 'finish_reason': 'stop',
                    'message': {'role': 'assistant', 'content': json.dumps(content)}}])
            decoded, count = w.management_selection_response(response(TRAINED, value), lease, a)
            self.assertEqual(count, 1)
            self.assertEqual(decoded.choices[0].message.tool_calls[0].function.name, NAME)
            for model in ('qwen3.6:35b', TRAINED + '-copy'):
                with self.assertRaisesRegex(ValueError, 'response_shape'):
                    w.management_selection_response(response(model, value), lease, a)
            bad = dict(value, request_nonce='0' * 32)
            with self.assertRaises(Exception):
                w.management_selection_response(response(TRAINED, bad), lease, a)

    def test_trained_model_does_not_authorize_unregistered_or_write_tools(self):
        for name in ('terminal', 'mcp__resp__unblock_ip',
                     'mcp__rule_write_a__temporarily_contain_ip'):
            a = agent(); a.model = TRAINED; r = request(); r['model'] = TRAINED
            r['tools'][0]['function']['name'] = name
            with patch.dict(w.os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify'}, clear=True):
                with self.assertRaisesRegex(RuntimeError, 'catalog_invalid'):
                    w.management_read_request(r, a, pending=True)

    def test_unknown_runtime_and_provider_do_not_get_projection(self):
        for field, value in [('model', TRAINED + ':latest'), ('provider', 'other'),
                             ('base_url', 'http://other/v1')]:
            a = agent(); a.model = TRAINED; setattr(a, field, value)
            r = dict(request(), model=a.model)
            with patch.dict(w.os.environ, {'CAPSTONE_MANAGEMENT_MODE': 'verify'}, clear=True):
                self.assertIs(w.management_read_request(r, a, pending=True), r)


if __name__ == '__main__':
    unittest.main()
