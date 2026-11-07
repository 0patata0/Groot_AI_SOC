import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'mcp'))
import security_rule_inventory as inv
from test_ids_method import H,NAME,receipt

QUESTION='IDS 관리자 예외 보여줘'


def policy(raw=b'suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.16.231/32\n'):
    rows,warnings=inv.threshold_statements(raw)
    return {'schema':1,'status':'partial' if warnings else 'observed','configuration_selected':True,
            'runtime_load_verified':False,'scope':'current_selected_threshold_configuration_not_engine_memory',
            'sha256':inv.digest(raw),'observed_at_kst':'2026-11-07T14:00:00+09:00',
            'entries':rows,'warnings':warnings,'statement_count':len(rows),'container_path':'/rules/threshold.in'}


class IdsThresholdTests(unittest.TestCase):
    def test_short_policy_questions_select_actual_read(self):
        for q in (QUESTION,'IDS 예외?','수리카타 threshold 확인해줘','Suricata 경보 억제 설정 보여줘',
                  'IDS 192.168.16.231 예외 맞아?'):
            with self.subTest(q=q):
                self.assertTrue(H.ids_policy_question(q));self.assertEqual(H.tool_scope(q),{NAME})
                schema={'type':'object','properties':{'target':{'type':'string','enum':['a:waf','a:suricata']}},'required':['target']}
                self.assertEqual(H.refine_read_schemas(q,{NAME:schema},[])[NAME]['properties']['target']['enum'],['a:suricata'])
                self.assertTrue(H.missing_reads(q,[]));self.assertFalse(H.missing_reads(q,[receipt(threshold_configuration=policy())]))

    def test_writes_other_devices_concepts_and_incidents_remain_normal_route(self):
        for q in ('IDS 관리자 예외 추가해줘','IDS 예외 등록해줘','IDS 예외 설정해줘',
                  'IDS 예외 지워줘','IDS 예외가 왜 적용 안됐지? 원인 조사해줘',
                  'IDS와 WAF 예외 보여줘','IDS suppress가 무슨 뜻이야? 도구 없이 설명만 해줘'):
            with self.subTest(q=q):self.assertFalse(H.ids_policy_question(q))

    def test_actual_policy_table_preserves_scope_source_and_kst(self):
        out=H.service_report(QUESTION,[receipt(threshold_configuration=policy())])
        for text in ('1 / 2001219','출발지','192.168.16.231/32','해당 경보 억제','14:00:00+09:00','SHA256','다른 공격 전체 면제를 뜻하지 않습니다'):
            self.assertIn(text,out)
        self.assertNotIn('```',out);self.assertNotIn('설정 변경 완료',out)
        # No project administrator constant: a different observed destination is preserved.
        other=policy(b'suppress gen_id 1, sig_id 42, track by_dst, ip 192.0.2.8/32\n')
        out=H.service_report(QUESTION,[receipt(threshold_configuration=other)])
        self.assertIn('목적지',out);self.assertIn('192.0.2.8/32',out);self.assertNotIn('192.168.16.231',out)

    def test_missing_or_forged_policy_is_incomplete_not_no_exception(self):
        for value in (None,{}, {'status':'unavailable'}, {**policy(),'configuration_selected':False},
                      {**policy(),'sha256':'bad'}, {**policy(),'statement_count':0},
                      {**policy(),'runtime_load_verified':True}):
            row=receipt(threshold_configuration=value)
            self.assertTrue(H.missing_reads(QUESTION,[row]));self.assertIn('검증하지 못했습니다',H.service_report(QUESTION,[row]))
        row=receipt(threshold_configuration=policy());row['result_sha256']='0'*64
        self.assertTrue(H.missing_reads(QUESTION,[row]));self.assertNotIn('192.168.16.231',H.service_report(QUESTION,[row]))

    def test_unparsed_policy_preserved_with_partial_status(self):
        data=policy(b'suppress gen_id 1, sig_id 42\nnew_kind unknown\n')
        row=receipt(threshold_configuration=data);out=H.service_report(QUESTION,[row])
        self.assertTrue(H.missing_reads(QUESTION,[row]));self.assertIn('미해석 2행',out);self.assertIn('new_kind unknown',out)
        self.assertIn('전체 확인 미완료',out)

    def test_latest_failure_never_reuses_success_and_is_not_blindly_repeated(self):
        good=receipt(threshold_configuration=policy());bad=receipt(threshold_configuration=None)
        out=H.service_report(QUESTION,[good,bad]);self.assertNotIn('192.168.16.231',out)
        self.assertTrue(H.missing_reads(QUESTION,[good,bad]));self.assertEqual(H.refine_read_schemas(QUESTION,{NAME:{}},[good,bad]),{})

    def test_valid_empty_selected_file_and_unresolved_variables_are_distinct(self):
        out=H.service_report(QUESTION,[receipt(threshold_configuration=policy(b'# no entries'))])
        self.assertIn('조회한 파일에 한정',out);self.assertNotIn('전체 예외 없음',out)
        out=H.service_report(QUESTION,[receipt(threshold_configuration=policy(b'suppress gen_id 1, sig_id 42, track by_src, ip $HOME_NET'))])
        self.assertIn('$HOME_NET',out);self.assertIn('실제 주소 범위는 별도 확인',out)


if __name__=='__main__':unittest.main()
