"""No firewall mutation without an exact, one-use operator decision."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('response_mcp', Path(__file__).with_name('response-mcp.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ResponseApprovalTests(unittest.TestCase):
    def decision(self, **updates):
        return {'req_id': 'a' * 16, 'status': 'approved', 'action': 'block', 'ip': '8.8.4.4', 'minutes': 10, 'by': 'admin', **updates}

    def run_approval(self, responses, action='block', minutes=10):
        with patch.object(m, 'BROKER_URL', 'http://broker'), patch.object(m, 'BROKER_TOKEN', 'secret-placeholder'), patch.object(m.time, 'sleep'), patch.object(m, '_broker', side_effect=responses) as call:
            result = m.request_approval('8.8.4.4', minutes, 'test', action)
        return result, call

    def test_missing_broker_never_mutates_block_or_release(self):
        with patch.object(m, 'BROKER_URL', ''), patch.object(m, 'run_agent_block') as run:
            for name in ('block_ip', 'unblock_ip'):
                self.assertTrue(m.call_tool(name, {'ip': '8.8.4.4', 'reason': 'test'})['isError'])
        run.assert_not_called()

    def test_approved_decision_must_be_consumed_with_exact_identity(self):
        result, call = self.run_approval([{'req_id': 'a'*16, 'posted': True}, self.decision(), self.decision(status='consumed')])
        self.assertEqual(result, ('approved', 'admin'))
        self.assertEqual(call.call_args.args, ('POST', '/consume', {'request_id': 'a'*16, 'action': 'block', 'ip': '8.8.4.4', 'minutes': 10}))

    def test_changed_identity_and_missing_approver_rejected(self):
        for changes in ({'ip':'8.8.8.8'}, {'action':'unblock'}, {'minutes':60}, {'req_id':'b'*16}, {'by':''}):
            result, call = self.run_approval([{'req_id':'a'*16,'posted':True}, self.decision(**changes)])
            self.assertEqual(result[0], 'error')
            self.assertEqual(call.call_count, 2)

    def test_failed_or_wrong_consumption_is_not_approval(self):
        for third in (OSError('offline'), self.decision(status='approved'), self.decision(status='consumed', minutes=60)):
            result, _ = self.run_approval([{'req_id':'a'*16,'posted':True}, self.decision(), third])
            self.assertEqual(result[0], 'error')

    def test_unblock_uses_own_zero_duration_approval(self):
        with patch.object(m, 'request_approval', return_value=('approved','admin')) as approval, patch.object(m, 'run_agent_block', return_value=(0,'ok','')) as run:
            self.assertFalse(m.call_tool('unblock_ip', {'ip':'8.8.4.4','reason':'release'})['isError'])
        approval.assert_called_once_with('8.8.4.4', 0, 'release', action='unblock')
        run.assert_called_once_with(['del','8.8.4.4','-','release'])

    def test_all_nonapproved_states_refuse_mutations(self):
        for state in ('denied','expired','error','unconfigured','consumed'):
            with patch.object(m, 'request_approval', return_value=(state,'')), patch.object(m, 'run_agent_block') as run:
                for name in ('block_ip','unblock_ip'):
                    self.assertTrue(m.call_tool(name, {'ip':'8.8.4.4','reason':'test'})['isError'])
                run.assert_not_called()

    def test_read_only_list_does_not_request_approval(self):
        with patch.object(m, 'request_approval') as approval, patch.object(m, 'run_agent_block', return_value=(0,'[]','')):
            self.assertFalse(m.call_tool('list_blocks', {})['isError'])
        approval.assert_not_called()

if __name__ == '__main__':
    unittest.main()
