"""Full-device reads must not be satisfied by a custom subset or stale page."""
import copy
import hashlib
import json
import unittest
import harness as H


def fixture(target='b:wazuh', *, origin='all', view='summary', correlation=False,
            rule_id=None, offset=0, limit=20, total=None, snapshot='a'*64):
    if total is None:total=1 if origin!='all' else 2
    args={'target':target,'origin':origin,'view':view,'correlation_only':correlation,
          'offset':offset,'limit':limit}
    if offset:args['snapshot_id']=snapshot
    if rule_id is not None:args['rule_id']=rule_id
    rows=[{'id':rule_id or str(5712+i),'origin':origin if origin!='all' else 'builtin' if i==0 else 'custom','source':'/var/ossec/ruleset/rules/sshd.xml',
           'configuration':'selected','description':'fixture','correlation':True,
           'details':{'frequency':'8','timeframe':'120','if_matched_sid':'5710','same_source_ip':''}}
          for i in range(offset,min(offset+limit,total))]
    data={'schema_version':1,'target':target,'scope':'installed_rule_definitions_and_configuration_selection',
          'runtime_load_verified':False,'status':'complete','observed_at_kst':'2026-10-31T13:00:00+09:00',
          'snapshot_id':snapshot,'counts':{'definitions':2,'builtin':1,'custom':1,'configured':2,
              'excluded':0,'correlation':2,'temporal_correlation':1,'dependency_rules':1},
          'filter':{'origin':origin,'rule_id':rule_id,'correlation_only':correlation},'view':view,
          'matched_count':total,'offset':offset,'limit':limit,'returned_count':len(rows),
          'next_offset':offset+len(rows) if offset+len(rows)<total else None,'rules':rows,'warnings':[],
          'files':[],'runtime':{},'exclusions_and_updates':[]}
    call={'server':'rule-'+target[0],'name':'get_security_rules','arguments':args,'is_error':False}
    return seal(call,data)


def seal(call,data):
    body={k:v for k,v in data.items() if k!='receipt_sha256'}
    data['receipt_sha256']=hashlib.sha256(json.dumps(body,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    call['result']=json.dumps(data,ensure_ascii=False)
    call['result_sha256']=hashlib.sha256(call['result'].encode()).hexdigest()
    return call


class FullInventory(unittest.TestCase):
    def test_short_device_requests_select_full_read_only_tools(self):
        for q,target in [('WAF 룰','a:waf'),('IPS 룰','a:suricata'),('와주 룰','b:wazuh')]:
            with self.subTest(q=q):
                self.assertEqual(H.missing_reads(q,[]),[target])
                self.assertEqual(H.tool_scope(q),{'mcp__rule_'+target[0]+'__get_security_rules'})
        self.assertEqual(H.tool_scope('FW 룰'),{'mcp__resp__get_firewall_rules'})
        self.assertIsNotNone(H.scope_notice('룰 조회해줘'))

    def test_official_correlation_conditions_and_vendor_id_are_queryable(self):
        q='Wazuh ID 5712 조건 보여줘'
        c=fixture(view='details',rule_id='5712',total=1)
        self.assertEqual(H.missing_reads(q,[c]),[])
        rendered=H.read_report(q,[c])
        for key in ('frequency','timeframe','if_matched_sid','same_source_ip','5710'):
            self.assertIn(key,rendered)
        q='Wazuh 상관분석 룰 조건 조회'
        self.assertTrue(H.security_inventory_request(q)['correlation_only'])
        self.assertEqual(H.missing_reads(q,[fixture(view='details',correlation=True)]),[])

    def test_custom_subset_cannot_satisfy_default_or_builtin_request(self):
        c=fixture(origin='custom')
        self.assertEqual(H.missing_reads('Wazuh 룰',[c]),['b:wazuh'])
        self.assertEqual(H.missing_reads('Wazuh 기본 룰',[c]),['b:wazuh'])
        self.assertEqual(H.missing_reads('Wazuh 커스텀 룰',[c]),[])

    def test_full_list_requires_contiguous_pages_same_snapshot(self):
        q='Wazuh 룰 전체 상세 목록 조회'
        first=fixture(view='details',limit=1)
        last=fixture(view='details',offset=1,limit=1)
        self.assertTrue(H.missing_reads(q,[first]))
        self.assertEqual(H.missing_reads(q,[first,last]),[])
        changed=fixture(view='details',offset=1,limit=1,snapshot='b'*64)
        self.assertTrue(H.missing_reads(q,[first,changed]))
        self.assertTrue(H.missing_reads(q,[last]))

    def test_snapshot_error_or_malformed_evidence_never_becomes_absence(self):
        q='Wazuh 룰'
        good=fixture()
        bad=copy.deepcopy(good);bad['is_error']=True
        self.assertTrue(H.missing_reads(q,[good,bad]))
        for field,value in [('returned_count',3),('snapshot_id','invalid'),('rules',[]),
                            ('warnings',['unread source']),('runtime_load_verified',True)]:
            c=fixture();data=json.loads(c['result']);data[field]=value;seal(c,data)
            self.assertTrue(H.missing_reads(q,[c]),field)
        c=fixture();c['result_sha256']='f'*64
        self.assertTrue(H.missing_reads(q,[c]))

    def test_schema_binds_scope_and_next_page_to_actual_receipt(self):
        alias='mcp__rule_b__get_security_rules'
        q='Wazuh 룰 전체 상세 목록 조회';first=fixture(view='details',limit=1)
        schema=H.refine_read_schemas(q,{alias:{}},[first])[alias]['anyOf'][0]
        self.assertEqual(schema['properties']['snapshot_id'],{'enum':['a'*64]})
        self.assertEqual(schema['properties']['offset'],{'enum':[1]})
        self.assertEqual(schema['properties']['origin'],{'enum':['all']})
        self.assertFalse(schema['additionalProperties'])

    def test_rule_id_schema_survives_agent_identity_refinement(self):
        alias='mcp__rule_b__get_security_rules'
        for question in ('Wazuh ID 5712 조건 보여줘','Wazuh 룰 ID 5712 조회'):
            self.assertIsNone(H.read_plan(question))
            refined=H.refine_read_schemas(question,{alias:{}},[])
            self.assertEqual(set(refined),{alias})
            properties=refined[alias]['anyOf'][0]['properties']
            self.assertEqual(properties['rule_id'],{'enum':['5712']})
            self.assertEqual(properties['view'],{'enum':['details']})
        for question in ('Wazuh 에이전트 ID 004 조회','Wazuh agent ID 004 조회'):
            self.assertIsNone(H.security_inventory_request(question))
            self.assertEqual(H.read_plan(question)['kind'],'agent_identity')

    def test_device_specific_report_does_not_add_other_devices(self):
        for question,target in (('WAF 룰','a:waf'),('IDS 룰','a:suricata')):
            self.assertNotIn('Wazuh',H.read_report(question,[fixture(target=target)]))

    def test_no_current_read_plan_for_write_incident_or_quoted_instruction(self):
        for q in ('Wazuh 룰 삭제해줘','IDS 룰 바꿔줘','WAF 룰 위험 원인을 분석해줘',
                  'Wazuh 룰 조회하지 마','"WAF 룰 보여줘"'):
            self.assertIsNone(H.security_inventory_request(q),q)
        for q in ('Wazuh 룰 조회하지 마','WAF 룰 조회하지 마'):
            self.assertFalse(H.structured_read(q))



if __name__=='__main__':unittest.main()
