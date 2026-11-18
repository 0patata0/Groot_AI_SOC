"""Calendar days constrain first event reads without changing follow-up scopes."""
import copy
from datetime import datetime
import unittest
from jsonschema import Draft202012Validator, ValidationError
import harness as h
import test_evidence_report as f

AT='2026-11-18T03:19:09.431739+09:00'
def schema():
    return {'type':'object','properties':{'since_kst':{'type':'string'},'until_kst':{'type':'string'},
        'lookback_minutes':{'type':'integer'},'source_ip':{'type':'string'}},'additionalProperties':False}

class InitialEventDay(unittest.TestCase):
    def test_non_temporal_particles_and_repeated_day_mentions_keep_the_calendar_day(self):
        # The first full sentence failed on both actual bots; keep it verbatim.
        questions=(
            '어제 WAF·IDS 경보를 개별 내역까지 상세 표로 조사해줘. 출발지를 비교하고 지금 임시 IP 차단 목록도 보여줘',
            '어제 WAF와 IDS 사이의 출발지를 비교해줘',
            '어제 IDS 경보 5건까지만 보여줘',
            '어제 IDS 경보를 첫 행부터 보여줘',
            '어제 IDS와 어제 WAF 경보 조사해줘',
            '어제 경보는 원문 말고 요약으로 보여줘',
            '어제 경보를 JSON 제외하고 표로 보여줘',
            '어제 IDS 12시그니처 경보와 5분류 결과를 조사해줘')
        for question in questions:
            with self.subTest(question=question):
                raw={name:schema() for name in (f.MOD,f.SUR,'mcp__security_events__search_wazuh_alerts')}
                result=h.initial_event_day_schemas(question,raw,[],AT)
                for name in raw:
                    self.assertEqual(result[name]['properties']['since_kst']['const'],'2026-11-17T00:00:00+09:00')
                    self.assertEqual(result[name]['properties']['until_kst']['const'],'2026-11-17T23:59:59.999999+09:00')
                    self.assertNotIn('lookback_minutes',result[name]['properties'])

    def test_equivalent_today_aliases_are_one_day_but_mixed_days_stay_unbound(self):
        raw={f.MOD:schema()}
        bound=h.initial_event_day_schemas('오늘 WAF와 금일 IDS 경보를 조사해줘',raw,[],AT)
        self.assertEqual(bound[f.MOD]['properties']['until_kst']['const'],AT)
        for q in ('오늘 IDS와 어제 WAF 경보 조사해줘','어제 이후 WAF 경보 조사해줘','어제까지 IDS 경보 보여줘',
                  '어제는 제외하고 IDS 경보 보여줘','어제와 11월 16일 WAF 경보 조사해줘'):
            self.assertEqual(h.initial_event_day_schemas(q,raw,[],AT),raw,q)

    def test_actual_time_qualifiers_are_not_replaced_with_a_whole_day(self):
        raw={f.MOD:schema()}
        for qualifier in ('09시부터 10시까지','9시 이후','09:00~10:00','오전','오후','새벽','밤',
                          '30분간','1시간 전','같은 시각','탐지 시점부터','종료 시간까지'):
            q='어제 '+qualifier+' WAF 경보 조사해줘'
            self.assertEqual(h.initial_event_day_schemas(q,raw,[],AT),raw,q)

    def test_yesterday_binds_closed_calendar_day_and_rejects_rolling_24_hours(self):
        raw={f.MOD:schema(),f.SUR:schema(),f.BLOCK:{'type':'object','properties':{}}};before=copy.deepcopy(raw)
        actual=h.initial_event_day_schemas('어제 WAF·IDS 경보 조사해줘',raw,[],AT)
        for name in (f.MOD,f.SUR):
            validator=Draft202012Validator(actual[name])
            validator.validate({'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-17T23:59:59.999999+09:00'})
            with self.assertRaises(ValidationError):validator.validate({'lookback_minutes':1440})
            with self.assertRaises(ValidationError):validator.validate({
                'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-18T00:00:00+09:00'})
            upper=datetime.fromisoformat(actual[name]['properties']['until_kst']['const'])
            self.assertLess(upper,datetime.fromisoformat('2026-11-18T00:00:00+09:00'))
            self.assertGreaterEqual(upper,datetime.fromisoformat('2026-11-17T23:59:59.999000+09:00'))
        self.assertEqual(actual[f.BLOCK],raw[f.BLOCK]);self.assertEqual(raw,before)

    def test_today_ends_at_actual_turn_clock_without_removing_source_filter(self):
        for day in ('오늘','금일'):
            actual=h.initial_event_day_schemas(day+' WAF 경보 조사해줘',{f.MOD:schema()},[],AT)[f.MOD]
            Draft202012Validator(actual).validate({'since_kst':'2026-11-18T00:00:00+09:00','until_kst':AT,'source_ip':'192.0.2.232'})

    def test_qualified_ambiguous_quoted_or_other_timezone_days_are_not_reinterpreted(self):
        raw={f.MOD:schema()}
        for question in ('최근24시간 WAF 경보 조사','어제 오후3시 WAF 경보 조사','어제부터 오늘까지 WAF 경보 조사',
                         '어제 UTC WAF 경보 조사','어제 대략 WAF 경보 조사','어제 말고 오늘 WAF 경보 조사',
                         '"어제"라는 말 뜻을 설명해줘','2026-11-17 WAF 경보 조사'):
            self.assertEqual(h.initial_event_day_schemas(question,raw,[],AT),raw,question)
        self.assertEqual(h.initial_event_day_schemas('어제 WAF 경보',raw,[],'2026-11-17T18:19:09+00:00'),raw)

    def test_existing_bindings_and_successful_tool_followups_keep_their_scope(self):
        raw={f.MOD:schema(),f.SUR:schema()};raw[f.SUR]['properties']['since_kst']['const']='2026-11-17T12:00:00+09:00'
        actual=h.initial_event_day_schemas('어제 WAF IDS 경보 조사',raw,[f.call(f.MOD)],AT)
        self.assertEqual(actual,raw)
        failed=f.call(f.MOD,{'error':'unavailable'},is_error=True)
        actual=h.initial_event_day_schemas('어제 WAF 경보 조사',raw,[failed],AT)
        self.assertIn('const',actual[f.MOD]['properties']['since_kst'])

    def test_calendar_binding_survives_the_existing_historical_read_refinement(self):
        raw={name:schema() for name in (f.MOD,f.SUR)};q='어제 WAF·IDS 경보 조사해줘. 출발지 겹쳤어?'
        bound=h.initial_event_day_schemas(q,raw,[],AT)
        selected=h.refine_read_schemas(q,bound,[],())
        wire=h.selection_schema(selected,8,question=q)
        plan={'calls':[{'tool':name,'arguments':{'since_kst':'2026-11-17T00:00:00+09:00',
            'until_kst':'2026-11-17T23:59:59.999999+09:00'}} for name in (f.MOD,f.SUR)]}
        h.validated_selection(plan,wire)
        for item in selected.values():
            self.assertNotIn('lookback_minutes',item['properties'])
            self.assertNotIn('lookback_minutes',item['required'])

    def test_failed_detail_wording_and_cross_device_comparison_keep_exact_window_after_refinement(self):
        for q in ('어제 WAF·IDS 경보를 개별 내역까지 상세 표로 조사해줘. 출발지를 비교하고 지금 임시 IP 차단 목록도 보여줘',
                  '어제 WAF와 IDS 사이의 출발지를 비교해줘'):
            raw={name:schema() for name in (f.MOD,f.SUR)}
            selected=h.refine_read_schemas(q,h.initial_event_day_schemas(q,raw,[],AT),[],())
            wire=h.selection_schema(selected,8,question=q)
            args={'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-17T23:59:59.999999+09:00'}
            h.validated_selection({'calls':[{'tool':name,'arguments':args} for name in (f.MOD,f.SUR)]},wire)
            for name in (f.MOD,f.SUR):
                with self.assertRaises(ValidationError):
                    h.validated_selection({'calls':[{'tool':name,'arguments':{'lookback_minutes':1440,'until_kst':AT}}]},wire)

if __name__=='__main__':unittest.main()
