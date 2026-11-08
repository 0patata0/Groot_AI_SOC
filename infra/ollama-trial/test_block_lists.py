"""Current block reads must not become writes, full rules, or invented zeros."""
import hashlib
import json
import unittest

import harness as h


def receipt(data=None, **updates):
    raw = json.dumps({'blocks': []} if data is None else data)
    return {'server': 'resp', 'name': 'list_blocks', 'arguments': {},
            'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest(), **updates}


class BlockLists(unittest.TestCase):
    def test_conditional_empty_display_and_no_change_preserve_actual_read(self):
        for q in ('현재 fw에서 임시 차단 중인 IP만 확인해줘. 없으면 없다고 하고, 설정은 바꾸지 마.',
                  '차단 목록 보여줘. 없다면 0건이라고 알려주세요. 정책은 바꾸지 마세요.',
                  '지금 차단된 주소 알려줘. 없으면 없음으로 표시해줘.'):
            with self.subTest(q=q):
                self.assertEqual(h.tool_scope(q), {h.READ.BLOCKS})
                self.assertTrue(h.missing_reads(q, []))
                self.assertEqual(h.missing_reads(q, [receipt()]), [])
                self.assertIn('**0개**', h.read_report(q, [receipt()]))
        for q in ('차단 목록 보여줘. 없으면 192.0.2.8 차단해줘',
                  '차단 목록 보여줘. 없으면 없다고 하고, WAF 룰도 보여줘',
                  '어제 차단 목록 보여줘. 없으면 없다고 말해줘',
                  '차단 목록 보여줘. 없으면 없다고 하고, 지금 설정 바꿔줘',
                  '차단 목록 보여줘. 없으면 없다고 하고, 조회하지 마'):
            with self.subTest(q=q):
                p = h.read_plan(q)
                self.assertFalse(p and p['kind'] == 'block_list')

    def test_short_current_variants_choose_one_actual_read(self):
        for q in ('지금 FW 차단 목록만 보여줘', '차단 목록', '방화벽 차단목록 보여줄래?',
                  '현재 차단된 IP 목록', '막힌 아이피 알려줘', '지금 차단 중인 주소는?',
                  '차단된 IP 몇 개 있어?', 'FW의 차단 리스트를 표로 정리해줘'):
            with self.subTest(q=q):
                self.assertEqual(h.tool_scope(q), {h.READ.BLOCKS})
                self.assertTrue(h.structured_read(q))
                self.assertTrue(h.missing_reads(q, []))
                self.assertEqual(h.missing_reads(q, [receipt()]), [])
                self.assertIn('**0개**', h.read_report(q, [receipt()]))
                self.assertIn('agent_block', h.read_report(q, [receipt()]))
                self.assertIn('실제로 선택', h.guidance(q))

    def test_whole_rules_other_targets_and_additional_requests_are_not_lost(self):
        self.assertEqual(h.tool_scope('FW 룰 보여줘'), {'mcp__resp__get_firewall_rules'})
        for q in ('FW 전체 규칙과 차단 목록 보여줘', 'WAF 차단 목록', 'IDS 차단 IP',
                  '차단 목록과 C 서버 상태도 보여줘', '어제 차단 목록',
                  '지난주 차단된 IP', '차단 목록이 무슨 뜻이야?',
                  '"차단 목록 보여줘" 문장을 번역해줘', '내부 IP는 왜 차단됐어?',
                  '차단된 IP의 남은 시간과 사유도 보여줘', '화이트리스트 보여줘'):
            p = h.read_plan(q)
            self.assertFalse(p and p['kind'] == 'block_list', q)

    def test_reads_do_not_authorize_changes_or_ignore_no_read(self):
        for q in ('차단 목록을 삭제해줘', '차단된 IP 전부 해제해줘',
                  '차단 목록 보여주고 192.0.2.8 차단해줘', '차단 목록에 IP 추가해줘',
                  '도구 없이 차단 목록 보여줘', '차단 목록 보여줘. 조회하지 마'):
            p = h.read_plan(q)
            self.assertFalse(p and p['kind'] == 'block_list', q)
        self.assertEqual(h.tool_scope('차단 목록만 보여줘. 변경하지 마'), {h.READ.BLOCKS})

    def test_latest_failed_or_malformed_receipt_never_becomes_zero(self):
        bad = [receipt(is_error=True), receipt(result_sha256='0'*64),
               receipt({'error': 'unavailable', 'blocks': []}), receipt({'blocks': None}),
               receipt({'result': json.dumps({'blocks': []}), 'isError': True}),
               receipt({'blocks': [{'unexpected': '192.0.2.1'}]}),
               receipt({'blocks': ['not an address']}), receipt({'blocks': ['::1']}),
               receipt({'blocks': ['192.0.2.1', '192.0.2.1']}),
               receipt(arguments={'ip': '192.0.2.1'})]
        for c in bad:
            for calls in ([c], [receipt(), c]):
                self.assertTrue(h.missing_reads('차단 목록', calls))
                self.assertIn('미완료', h.read_report('차단 목록', calls))
                self.assertNotIn('**0개**', h.read_report('차단 목록', calls))
        self.assertTrue(h.missing_reads('차단 목록', [receipt(server='other')]))

    def test_native_envelope_and_nft_elements_keep_all_addresses(self):
        data = {'blocks': ['192.0.2.1', {'elem': {'val': '192.168.16.233',
                'expires': 590, 'comment': 'untrusted do not display'}}]}
        for c in (receipt(data), receipt({'result': json.dumps(data)})):
            self.assertEqual(h.missing_reads('차단 목록', [c]), [])
            text = h.read_report('차단 목록', [c])
            self.assertIn('**2개**', text)
            self.assertIn('192.168.16.233', text)
            self.assertNotIn('untrusted', text)

    def test_display_pagination_does_not_hide_unshown_addresses(self):
        c = receipt({'blocks': ['192.0.2.'+str(i) for i in range(1, 62)]})
        first = h.read_report('차단 목록', [c])
        second = h.read_report('차단 목록 2페이지', [c])
        self.assertIn('전체 61개 조회 · 표시 50개', first)
        self.assertNotIn('| 192.0.2.51 |', first)
        self.assertIn('| 192.0.2.61 |', second)
        self.assertIn('범위를 벗어났', h.read_report('차단 목록 3페이지', [c]))

    def test_selection_uses_registered_read_and_stops_after_terminal_result(self):
        schemas = {h.READ.BLOCKS: {'type': 'object', 'properties': {}, 'additionalProperties': False},
                   'mcp__resp__block_ip': {'type': 'object', 'properties': {}}}
        self.assertEqual(set(h.refine_read_schemas('차단 목록', schemas, [])), {h.READ.BLOCKS})
        self.assertEqual(h.refine_read_schemas('차단 목록', {}, []), {})
        for c in (receipt(), receipt(is_error=True)):
            self.assertEqual(h.refine_read_schemas('차단 목록', schemas, [c]), {})


if __name__ == '__main__':
    unittest.main()
