"""Native evidence context preserves real ledger/wrapper binding, without dispatch."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
import soc_management_run as w

MOD='mcp__security_events__search_modsecurity_alerts'
SUR='mcp__security_events__search_suricata_alerts'
BLOCK='mcp__resp__list_blocks'
Q='어제 WAF·IDS 경보를 조사하고 현재 임시 IP 차단도 확인해줘.'
AT='2026-11-18T05:00:00+09:00'

def records():
    ledger=[];receipts=[]
    for name in (MOD,SUR,BLOCK):
        value={'blocks':[]} if name==BLOCK else {'source':'modsecurity' if name==MOD else 'suricata','alerts':[]}
        raw=json.dumps({'result':json.dumps(value,ensure_ascii=False)},ensure_ascii=False)
        ledger.append({'tool':name,'arguments':{},'result_state':'returned','result_sha256':hashlib.sha256(raw.encode()).hexdigest()})
        receipts.append({'tool':name,'output':raw,'is_error':False})
    return ledger,receipts

class NativeContext(unittest.TestCase):
    def setUp(self):
        self.h=w.chat_lookup_harness();self.chat={'request':Q,'requested_at_kst':AT}
        self.catalog={n:{'type':'object'} for n in (MOD,SUR,BLOCK)}

    def run_context(self,ledger,receipts,catalog=None):
        with patch.object(w,'diagnostic_contract',return_value=self.h.CONTRACT):
            return w.native_incident_report_context(self.chat,ledger,receipts,self.catalog if catalog is None else catalog,self.h)

    def test_preserves_original_wrapper_bytes_order_and_current_inventory(self):
        ledger,receipts=records();before=copy.deepcopy((ledger,receipts))
        context,calls=self.run_context(ledger,receipts)
        self.assertEqual(before,(ledger,receipts));self.assertEqual(len(calls),3)
        self.assertEqual([c['result'] for c in calls],[r['output'] for r in receipts])
        self.assertEqual(context['current_ip_inventory']['returned_ip_count'],0)
        self.assertEqual(context['current_ip_inventory']['receipt_sha256'],ledger[-1]['result_sha256'])
        self.assertEqual(len(context['native_read_ledger_sha256']),64)

    def test_changed_missing_extra_or_protected_receipts_are_not_silently_dropped(self):
        ledger,receipts=records()
        variants=[(ledger,receipts[:-1]),(ledger,receipts+[copy.deepcopy(receipts[0])]),
            ([dict(ledger[0],result_sha256='0'*64),*ledger[1:]],receipts)]
        for left,right in variants:self.assertIsNone(self.run_context(left,right))
        catalog={**self.catalog,'mcp__resp__block_ip':{'type':'object'}}
        self.assertIsNone(self.run_context(ledger,receipts,catalog))

    def test_a_newest_current_list_failure_does_not_inherit_old_zero(self):
        ledger,receipts=records();raw=json.dumps({'error':'unavailable'})
        ledger.append({'tool':BLOCK,'arguments':{},'result_state':'error','result_sha256':hashlib.sha256(raw.encode()).hexdigest()})
        receipts.append({'tool':BLOCK,'output':raw,'is_error':True})
        self.assertIsNone(self.run_context(ledger,receipts))

    def test_partial_required_sensor_or_current_list_cannot_become_a_report(self):
        ledger,receipts=records()
        for i in range(3):self.assertIsNone(self.run_context(ledger[:i]+ledger[i+1:],receipts[:i]+receipts[i+1:]))

if __name__=='__main__':unittest.main()
