"""Calendar days constrain first event reads without changing follow-up scopes."""
import copy
import unittest
from jsonschema import Draft202012Validator, ValidationError
import harness as h
import test_evidence_report as f

AT='2026-11-18T03:19:09.431739+09:00'
def schema():
    return {'type':'object','properties':{'since_kst':{'type':'string'},'until_kst':{'type':'string'},
        'lookback_minutes':{'type':'integer'},'source_ip':{'type':'string'}},'additionalProperties':False}

class InitialEventDay(unittest.TestCase):
    def test_yesterday_binds_calendar_midnights_and_rejects_rolling_24_hours(self):
        raw={f.MOD:schema(),f.SUR:schema(),f.BLOCK:{'type':'object','properties':{}}};before=copy.deepcopy(raw)
        actual=h.initial_event_day_schemas('어제 WAF·IDS 경보 조사해줘',raw,[],AT)
        for name in (f.MOD,f.SUR):
            validator=Draft202012Validator(actual[name])
            validator.validate({'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-18T00:00:00+09:00'})
            with self.assertRaises(ValidationError):validator.validate({'lookback_minutes':1440})
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
            'until_kst':'2026-11-18T00:00:00+09:00'}} for name in (f.MOD,f.SUR)]}
        h.validated_selection(plan,wire)
        for item in selected.values():
            self.assertNotIn('lookback_minutes',item['properties'])
            self.assertNotIn('lookback_minutes',item['required'])

if __name__=='__main__':unittest.main()
