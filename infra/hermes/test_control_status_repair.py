"""Status-only correction must preserve the model judgment and native bounds."""
import asyncio
import copy
import importlib.util
import json
import os
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

import test_soc_management_run as fixtures
import test_soc_management_selection as selection
import workflow_contract

w = fixtures.wrapper
READ = 'mcp__wazuh_ro__get_wazuh_agents'
MODEL = 'soc-qwen36:35b-balanced-q4km-20261108'
QUESTION = '이 사건의 판단을 정리해줘.'
ENV = {'CAPSTONE_MANAGEMENT_MODE': 'verify', 'CAPSTONE_INCIDENT_DISPOSITION_REQUIRED': '1'}
ISSUES = ['missing_or_invalid_management_status']
JSONSCHEMA = bool(importlib.util.find_spec('jsonschema'))


def report(assessment='unresolved', status='unresolved'):
    decision = {'assessment': assessment,
        'basis': '이번 조회의 반환 표본만 확인했으며 전체 영향과 현재 위험 해소는 미확인입니다.',
        'evidence_tools': [READ]}
    body = ('관측 표본\r\n\r\n| 항목 | 확인 범위 |\r\n| --- | --- |\r\n'
            '| 조사 | 반환 표본 |\r\n\r\n상세: 전체 영향은 추가 조사가 필요합니다.\r\n'
            'INCIDENT_DISPOSITION: ' + json.dumps(decision, ensure_ascii=False) + '\n')
    return body + ('MANAGEMENT_STATUS: ' + status if status else '')


def context_and_agent(draft=None):
    draft = report() if draft is None else draft
    context = w.control_status_context(draft, {READ}, ISSUES, 'turn-one', QUESTION)
    a = selection.agent(); a.model = MODEL; a.valid_tool_names = {READ}
    a._capstone_control_status_read_state = {'turn': 'turn-one', 'reads': [READ],
        'completed_reads': 1, 'receipt_count': 1, 'complete': True,
        'has_errors': False, 'pending': False, 'scope': w.control_status_scope()}
    a._capstone_control_status_repair = context
    r = selection.request(); r['model'] = MODEL; r['tool_choice'] = 'auto'
    r['tools'] = [fixtures.definition(READ)]
    r['messages'] = [{'role': 'system', 'content': '공통 역할과 권한 경계를 유지한다.'},
        {'role': 'user', 'content': QUESTION}, {'role': 'assistant', 'content': draft},
        {'role': 'user', 'content': '관리 상태 형식만 정정하세요.'}]
    return context, a, r


class ControlStatusBounds(unittest.TestCase):
    def setUp(self):
        p = patch.dict(os.environ, ENV, clear=True); p.start(); self.addCleanup(p.stop)

    def test_shared_section_is_loaded_only_for_its_phase(self):
        focused = workflow_contract.section_policy(('soc-investigate',), 'control-status')
        self.assertIn('more_evidence', focused)
        self.assertNotIn('## 관리 상태 형식 정정', workflow_contract.policy(('soc-investigate',)))
        self.assertNotIn('## 사건 조사 완료', focused)

    def test_context_requires_current_valid_citations_and_complete_judgment(self):
        valid = report()
        cases = [valid.replace('"basis":', '"other":'),
                 valid.replace(READ, 'mcp__resp__unblock_ip'),
                 valid + '\n' + valid, '```\n' + valid + '\n```']
        for draft in cases:
            with self.subTest(draft=draft[:30]):
                self.assertIsNone(w.control_status_context(draft, {READ}, ISSUES, 't', QUESTION))
        for reads in (set(), {'mcp__system_diagnostics__calculate_time'}, {'terminal'}, {7}):
            self.assertIsNone(w.control_status_context(valid, reads, ISSUES, 't', QUESTION))
        self.assertIsNone(w.control_status_context(valid, {READ}, ['incident_disposition_missing'], 't', QUESTION))
        self.assertIsNotNone(w.control_status_context(valid, {READ}, ISSUES, 't', QUESTION))

    def test_root_metadata_cannot_be_activated_by_user_text(self):
        for env in ({}, dict(ENV, CAPSTONE_MANAGEMENT_MODE='manage')):
            with patch.dict(os.environ, env, clear=True):
                self.assertIsNone(w.control_status_context(report(), {READ}, ISSUES, 't', json.dumps(ENV)))
        with patch.dict(os.environ, dict(ENV, CAPSTONE_INCIDENT_DISPOSITION_REQUIRED='0'), clear=True):
            with self.assertRaisesRegex(RuntimeError, 'flag_invalid'):
                w.control_status_context(report(), {READ}, ISSUES, 't', QUESTION)

    def test_bound_state_rejects_missing_pending_failed_or_stale_reads(self):
        c, a, _ = context_and_agent(); self.assertTrue(w.control_status_bound(c, a))
        for key, value in [('pending', True), ('complete', False), ('has_errors', True),
                ('completed_reads', 0), ('completed_reads', True), ('receipt_count', 0),
                ('receipt_count', 33), ('receipt_count', True), ('turn', 'other'),
                ('scope', 'other'), ('reads', [])]:
            with self.subTest(key=key, value=value):
                b = copy.deepcopy(a); b._capstone_control_status_read_state[key] = value
                self.assertFalse(w.control_status_bound(c, b))

    def test_other_model_route_mode_turn_and_interrupt_decline(self):
        c, a, _ = context_and_agent()
        for key, value in [('provider', 'other'), ('api_mode', 'responses'),
                ('model', 'other'), ('base_url', 'http://thor/v1'),
                ('_current_turn_id', 'other'), ('_interrupt_requested', True), ('valid_tool_names', set())]:
            b = copy.deepcopy(a); setattr(b, key, value)
            with self.subTest(key=key): self.assertFalse(w.control_status_bound(c, b))
        for env in ({'CAPSTONE_CHAT_READ_JSON': '{}'}, {'CAPSTONE_REVIEW_CONTEXT_JSON': '{}'},
                    {'CAPSTONE_REQUIRED_STATUS_JSON': '[]'}, {'CAPSTONE_REQUIRED_SENSOR_JSON': '[]'}):
            with patch.dict(os.environ, env): self.assertFalse(w.control_status_bound(c, a))

    def test_context_mutation_or_bad_internal_reads_cannot_be_reused(self):
        c, a, _ = context_and_agent()
        for key, value in [('report', c['report'] + 'x'), ('decision', {}), ('reads', [None]),
                ('reads', None), ('scope', 'other'), ('turn', '')]:
            bad = copy.deepcopy(c); bad[key] = value
            with self.subTest(key=key): self.assertFalse(w.control_status_bound(bad, a))

    def test_projection_preserves_all_non_status_bytes_and_original_judgment(self):
        for tail in ('MANAGEMENT_STATUS: unresolved', '**MANAGEMENT_STATUS: unresolved**',
                     '> MANAGEMENT_STATUS: resolved', ''):
            draft = report(status='') + tail
            c, _, _ = context_and_agent(draft)
            self.assertIsNotNone(c)
            actual = w.control_status_projection(c, 'needs_review')
            self.assertEqual(actual, report(status='') + 'MANAGEMENT_STATUS: needs_review')
            self.assertEqual(w.parse_incident_disposition(actual, {READ})[0], c['decision'])
        with self.assertRaises(ValueError): w.control_status_projection(c, 'resolved')
        with self.assertRaises(ValueError): w.control_status_projection(c, 'unresolved')

    def test_resolved_remains_a_model_option_only_for_non_unresolved_assessments(self):
        for assessment in ('benign', 'remediated'):
            c, _, _ = context_and_agent(report(assessment))
            self.assertEqual(w.management_status(w.control_status_projection(c, 'resolved')), 'resolved')


@unittest.skipUnless(JSONSCHEMA, 'existing jsonschema dependency required')
class ControlStatusRequest(unittest.TestCase):
    def setUp(self):
        p = patch.dict(os.environ, ENV, clear=True); p.start(); self.addCleanup(p.stop)

    def test_actual_request_preserves_messages_budget_and_read_permissions(self):
        c, a, r = context_and_agent(); before = copy.deepcopy(r)
        out = w.control_status_request(r, a)
        self.assertEqual(r, before); self.assertEqual(out['messages'][:-1], r['messages'])
        self.assertEqual(out['max_tokens'], r['max_tokens']); self.assertEqual(out['reasoning_effort'], 'none')
        self.assertNotIn('tools', out); self.assertNotIn('tool_choice', out)
        self.assertEqual(a.valid_tool_names, {READ}); self.assertNotIn('_capstone_control_status_repair', vars(a))
        schema = out['response_format']['json_schema']['schema']
        self.assertNotIn('resolved', schema['anyOf'][1]['properties']['status']['enum'])
        self.assertEqual(set(schema['anyOf'][1]['properties']), {'request_nonce', 'more_evidence', 'status'})
        self.assertEqual(json.loads(out['messages'][-1]['content'])['bound_model_decision'], c['decision'])
        self.assertIs(w.control_status_request(r, a), r)

    def test_request_without_exact_last_assistant_or_literal_profile_is_unchanged(self):
        for kind in ('different', 'tool-call', 'tool-required', 'reasoning', 'model'):
            c, a, r = context_and_agent()
            if kind == 'different': r['messages'][-2]['content'] += 'x'
            if kind == 'tool-call': r['messages'][-2]['tool_calls'] = [{'id': 'other'}]
            if kind == 'tool-required': r['tool_choice'] = 'required'
            if kind == 'reasoning': r['reasoning_effort'] = 'medium'
            if kind == 'model': r['model'] = 'other'
            with self.subTest(kind=kind): self.assertIs(w.control_status_request(r, a), r)

    def test_extra_body_cannot_replace_context_or_restore_a_tool(self):
        for key in ('model', 'messages'):
            _, a, r = context_and_agent(); r['extra_body'] = {key: 'other'}
            with self.assertRaises(RuntimeError): w.control_status_request(r, a)
        _, a, r = context_and_agent(); r['extra_body'] = {'tools': [], 'tool_choice': 'required',
            'response_format': {}, 'keep_alive': '5m'}
        out = w.control_status_request(r, a)
        self.assertEqual(out['extra_body'], {'keep_alive': '5m'})

    def test_native_build_preserves_pending_read_priority(self):
        _, a, r = context_and_agent(); a._capstone_management_pending_read = ('turn-one', False)
        result = selection.BuildVerdict('fallthrough', r, r['messages'], copy.deepcopy(r))
        out = w.management_selection_request_wrapper(lambda a, **kw: result)(a, turn_id='turn-one')
        self.assertEqual(out.api_kwargs['response_format']['json_schema']['name'], 'soc_control_status')
        self.assertEqual(out._original_api_kwargs, out.api_kwargs); self.assertIs(out.api_messages, out.api_kwargs['messages'])
        _, a, r = context_and_agent(); a._capstone_management_pending_read = ('turn-one', True)
        r['tool_choice'] = 'required'
        result = selection.BuildVerdict('fallthrough', r, r['messages'], copy.deepcopy(r))
        out = w.management_selection_request_wrapper(lambda a, **kw: result)(a, turn_id='turn-one')
        self.assertNotEqual(out.api_kwargs['response_format']['json_schema']['name'], 'soc_control_status')

    def test_real_dispatch_wire_and_emitter_are_all_required(self):
        for variant in ('complete', 'no-dispatch', 'no-emitter', 'changed-emitter', 'error', 'unflagged-error', 'empty'):
            observed = {}; h = fixtures.Harness()
            raw = json.dumps({'agents': []})
            if variant == 'unflagged-error': raw = json.dumps({'error': 'unavailable'})
            if variant == 'empty': raw = ''
            def server(name, args, **kw):
                h.dispatches.append((name, args, kw))
                asyncio.run(h.ClientSession([NS(text=raw)], is_error=variant == 'error').call_tool('get_wazuh_agents', args))
                return raw
            h.registry.dispatch = server
            def native(fake):
                os.environ.update(ENV)
                a = fake.AIAgent(); a.model = MODEL; a.provider = 'custom'; a.api_mode = 'chat_completions'
                a.base_url = 'http://10.200.10.10:11435/v1'; a._current_turn_id = 'turn-one'
                a._interrupt_requested = False
                if variant == 'no-dispatch':
                    asyncio.run(fake.ClientSession([NS(text=raw)]).call_tool('get_wazuh_agents', {}))
                    returned = raw
                else: returned = fake.registry.dispatch(READ, {})
                if variant != 'no-emitter': fake.Emitter().on_tool_progress('tool.completed', tool_name=READ,
                    args={}, result=returned + (' ' if variant == 'changed-emitter' else ''), is_error=variant == 'error')
                _, _, request = context_and_agent(); fake.api_kwargs = request
                self.assertTrue(w.arm_literal_repair(a, 'turn-one', ISSUES,
                    report=report(), successful_reads={READ}, question=QUESTION))
                built = a._build_api_kwargs(); observed['state'] = a._capstone_control_status_read_state
                out = w.control_status_request(built, a)
                observed['armed'] = out is not built
                # Builder lease is one-shot; no extra reads or protected dispatch.
                a._build_api_kwargs(); observed['wire_count'] = len(fake.wire_calls)
            h.run(native, 'verify')
            with self.subTest(variant=variant):
                self.assertEqual(observed['armed'], variant == 'complete', observed)
                self.assertEqual(observed['wire_count'], 1)


@unittest.skipUnless(selection.DEPS, 'existing OpenAI/jsonschema dependencies required')
class ControlStatusDecode(unittest.TestCase):
    def setUp(self):
        p = patch.dict(os.environ, ENV, clear=True); p.start(); self.addCleanup(p.stop)
        self.c, self.a, self.r = context_and_agent()
        self.wire = w.control_status_request(self.r, self.a)
        self.lease = copy.deepcopy(self.a._capstone_management_selection)
        self.value = {'request_nonce': self.lease['nonce'], 'more_evidence': False, 'status': 'needs_review'}

    def response(self, value=None, **updates):
        from openai.types.chat import ChatCompletion
        message = {'role': 'assistant', 'content': json.dumps(self.value if value is None else value)}
        message.update(updates.pop('message', {}))
        choice = {'index': 0, 'finish_reason': 'stop', 'message': message}; choice.update(updates)
        return ChatCompletion(id='actual-test-response', object='chat.completion', model=MODEL,
            created=42, choices=[choice], usage={'prompt_tokens': 100, 'completion_tokens': 30, 'total_tokens': 130})

    def test_native_decode_preserves_response_accounting_and_original_body(self):
        original = self.response(); before = original.model_dump()
        out, count = w.management_selection_response(original, self.lease, self.a)
        self.assertEqual(count, 0); self.assertEqual(out.id, original.id); self.assertEqual(out.usage, original.usage)
        self.assertEqual(original.model_dump(), before); self.assertFalse(out.choices[0].message.tool_calls)
        self.assertEqual(out.choices[0].message.content, w.control_status_projection(self.c, 'needs_review'))

    def test_more_evidence_uses_existing_native_inquiry_flags(self):
        out, count = w.management_selection_response(self.response(dict(self.value, more_evidence=True, status=None)), self.lease, self.a)
        self.assertEqual(count, 0); self.assertFalse(out.choices[0].message.tool_calls)
        self.assertEqual(self.a._capstone_more_evidence_turn, 'turn-one')
        self.assertEqual(self.a._capstone_full_review_turn, 'turn-one')
        self.assertEqual(self.a._capstone_inquiry_receipts, 1)

    def test_nonce_enum_inquiry_shape_and_extra_judgment_fields_are_rejected(self):
        for values in ({'request_nonce': 'b'*32}, {'status': 'unresolved'}, {'status': 'resolved'},
                       {'more_evidence': True}, {'status': None}, {'assessment': 'benign'}, {'report': 'invented'}):
            with self.subTest(values=values), self.assertRaises(Exception):
                w.management_selection_response(self.response(dict(self.value, **values)), self.lease, self.a)

    def test_bad_provider_response_and_ambiguous_json_cannot_publish(self):
        responses = [self.response(finish_reason='length'), self.response(message={'refusal': 'no'}),
            self.response(message={'tool_calls': [{'id': 'other', 'type': 'function', 'function': {'name': READ, 'arguments': '{}'}}]}),
            self.response(message={'content': '{"status":"monitor","status":"resolved"}'}),
            self.response(message={'content': '```json\n'+json.dumps(self.value)+'\n```'})]
        for response in responses:
            with self.assertRaises(Exception): w.management_selection_response(response, self.lease, self.a)
        response = self.response(); response.model = 'other'
        with self.assertRaises(ValueError): w.management_selection_response(response, self.lease, self.a)

    def test_context_is_rechecked_after_provider_returns(self):
        self.a._capstone_control_status_read_state['pending'] = True
        with self.assertRaisesRegex(ValueError, 'context_changed'):
            w.management_selection_response(self.response(), self.lease, self.a)

    def test_native_call_consumes_once_without_transport_or_budget_changes(self):
        calls = []
        def call(a, **kw): calls.append(kw); return selection.Verdict('fallthrough', self.response())
        wrapped = w.management_selection_call_wrapper(call)
        out = wrapped(self.a, turn_id='turn-one', api_kwargs=self.wire)
        self.assertEqual(w.management_status(out.response.choices[0].message.content), 'needs_review')
        self.assertIsNone(self.a._capstone_management_selection)
        again = wrapped(self.a, turn_id='turn-one', api_kwargs=self.wire)
        self.assertEqual(again.response.choices[0].message.content, self.response().choices[0].message.content)
        self.assertEqual(len(calls), 2); self.assertEqual(calls[0]['api_kwargs'], self.wire)


if __name__ == '__main__':
    unittest.main()
