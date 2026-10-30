import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from prepare_operational_evidence import complete_firewall, prepare
from refresh_soc_tool_descriptions import TOOL, refresh_row, reviewed_delta, source_entry


def catalogs():
    old={'tools':[{'server':'dummy','name':'dummy_'+str(i),'protected':i<8,
                  'description':'example','parameters':{'type':'object'}} for i in range(36)]}
    old['tools'] += [{'server':'resp','name':'mcp__resp__get_firewall_rules','protected':False,
                     'description':'FW','parameters':{'type':'object'}},
                    {'server':'rule-write-a','name':TOOL,'protected':True,'description':'old public-only',
                     'parameters':{'type':'object','properties':{'ip':{'type':'string'}}}}]
    new=copy.deepcopy(old);new.update(status='completed',model_calls=0,protected_calls=0,chat_posts=0)
    new['tools'][-1]['description']='public or RFC1918; Protected/management/infrastructure/DGX;10 minutes; never extend'
    entry={'name':'temporarily_contain_ip','description':new['tools'][-1]['description'],
           'inputSchema':new['tools'][-1]['parameters']}
    return old,new,'TOOLS = '+repr([entry])


def capture():
    _,new,_=catalogs()
    objects=[{'table':{'name':'filter','family':'inet'}},
             {'chain':{'name':'input','table':'filter','family':'inet','hook':'input','policy':'drop'}},
             {'rule':{'handle':3,'chain':'input','expr':[{'accept':None}]}},
             {'map':{'name':'map1','elem':[[1,2]]}}]
    base={'schema':1,'target':'a:firewall','snapshot':'b'*32,'sha256':'a'*64,
          'observed_at_kst':'2026-10-30T18:00:00+09:00','source':'nft -j -a -n list ruleset',
          'scope':'host namespace','excluded_scope':['other hosts','other network namespaces','legacy iptables'],
          'legacy_tables':{'ipv4':[],'ipv6':[]},'coverage_warnings':[],
          'counts':{'table':1,'chain':1,'rule':1,'map':1},'total_objects':4}
    calls=[]
    for offset in (0,2):
        page={**base,'offset':offset,'objects':objects[offset:offset+2],'complete':offset==2,
              'next_offset':2 if offset==0 else None}
        args={'limit':2} if offset==0 else {'limit':2,'offset':2,'snapshot':'b'*32}
        calls.append({'server':'resp','name':'get_firewall_rules','arguments':args,
                      'result':{'content':[{'type':'text','text':json.dumps(page)}],'isError':False}})
    return {**new,'calls':calls,'at_kst':'2026-10-30T18:00:00+09:00'}


def change_page(c,n,**updates):
    page=json.loads(c['calls'][n]['result']['content'][0]['text']);page.update(updates)
    c['calls'][n]['result']['content'][0]['text']=json.dumps(page)


class OperationalEvidenceTests(unittest.TestCase):
    def test_complete_pages_keep_policies_maps_and_scope(self):
        result=complete_firewall(capture());self.assertEqual(result['total_objects'],4)
        self.assertEqual(result['counts'],{'table':1,'chain':1,'rule':1,'map':1})
        self.assertEqual(result['base_chains'][0]['policy'],'drop')
        self.assertIn('other hosts',result['excluded_scope'])
        self.assertFalse(result['upstream_raw_hash_independently_recomputed'])

    def test_missing_first_or_last_page_is_not_complete(self):
        for part in (slice(1,None),slice(None,1)):
            c=capture();c['calls']=c['calls'][part]
            with self.assertRaises(ValueError):complete_firewall(c)

    def test_repeated_or_out_of_order_pages_rejected(self):
        for calls in ([0,0,1],[1,0],[0,1,1]):
            c=capture();c['calls']=[c['calls'][i] for i in calls]
            with self.assertRaises(ValueError):complete_firewall(c)

    def test_changed_snapshot_hash_scope_time_and_target_rejected(self):
        for field,value in [('snapshot','c'*32),('sha256','d'*64),('scope','different'),
                            ('observed_at_kst','2026-10-30T19:00:00+09:00'),('target','b:firewall')]:
            c=capture();change_page(c,1,**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):complete_firewall(c)

    def test_wrong_next_total_counts_and_complete_rejected(self):
        for page,changes in [(0,{'next_offset':3}),(1,{'total_objects':5}),(1,{'counts':{'rule':4}}),
                             (0,{'complete':True}),(1,{'next_offset':4})]:
            c=capture();change_page(c,page,**changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):complete_firewall(c)

    def test_failed_result_is_never_zero_rules(self):
        c=capture();c['calls'][0]['result']={'isError':True,'content':[{'type':'text','text':'unavailable'}]}
        with self.assertRaises(ValueError):complete_firewall(c)

    def test_call_arguments_must_bind_page(self):
        for args in ({'offset':2},{'offset':True,'snapshot':'b'*32},
                     {'offset':2,'snapshot':'c'*32},{'offset':2,'snapshot':'b'*32,'limit':True}):
            c=capture();c['calls'][1]['arguments']=args
            with self.subTest(args=args),self.assertRaises(ValueError):complete_firewall(c)

    def test_no_approved_write_or_model_capture_disguised_as_readonly(self):
        for k in ('model_calls','protected_calls','chat_posts'):
            c=capture();c[k]=1
            with self.assertRaises(ValueError):complete_firewall(c)

    def test_catalog_loss_unknown_dispatch_and_invalid_identity_rejected(self):
        c=capture();c['tools'].pop()
        with self.assertRaises(ValueError):complete_firewall(c)
        c=capture();c['calls'][0]['name']='list_blocks'
        with self.assertRaises(ValueError):complete_firewall(c)
        c=capture();change_page(c,0,snapshot='invalid')
        with self.assertRaises(ValueError):complete_firewall(c)

    def test_raw_utc_is_not_relabelled_as_kst(self):
        c=capture();change_page(c,0,observed_at_kst='2026-10-30T09:00:00+00:00')
        with self.assertRaises(ValueError):complete_firewall(c)

    def test_preparation_does_not_generate_answers_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'capture.json';p.write_text(json.dumps(capture()));out=Path(d)/'bundle'
            m=prepare(p,out);self.assertEqual(m['final_operational_cases_created'],0)
            self.assertFalse(any('answer' in p.name for p in out.iterdir()))
            with self.assertRaises(ValueError):prepare(p,out)


class DescriptionRefreshTests(unittest.TestCase):
    def test_only_reviewed_description_delta_accepted(self):
        old,new,source=catalogs();a,b=reviewed_delta(old,new,source)
        self.assertIn('RFC1918',b['description']);self.assertEqual(a['parameters'],b['parameters'])

    def test_schema_permission_or_extra_description_drift_refused(self):
        for field,value in [('protected',False),('parameters',{'type':'string'})]:
            old,new,source=catalogs();new['tools'][-1][field]=value
            with self.assertRaises(ValueError):reviewed_delta(old,new,source)
        old,new,source=catalogs();new['tools'][0]['description']='changed'
        with self.assertRaises(ValueError):reviewed_delta(old,new,source)

    def test_source_mismatch_or_duplicate_source_declaration_rejected(self):
        old,new,source=catalogs()
        with self.assertRaises(ValueError):reviewed_delta(old,new,source.replace('RFC1918','other'))
        with self.assertRaises(ValueError):source_entry(source+'\n'+source)

    def test_row_preserves_messages_arguments_and_input_object(self):
        old,new,_=catalogs();a,b=old['tools'][-1],new['tools'][-1]
        row={'id':'x','tools':[{'type':'function','function':{k:a[k] for k in ('name','description','parameters')}}],
             'messages':[{'role':'assistant','tool_calls':[{'function':{'name':TOOL,'arguments':{'ip':'203.0.113.4'}}}]}]}
        before=copy.deepcopy(row);updated,changed=refresh_row(row,a,b)
        self.assertTrue(changed);self.assertEqual(row,before);self.assertEqual(updated['messages'],row['messages'])
        self.assertEqual(updated['tools'][0]['function']['description'],b['description'])

    def test_unrelated_rows_unchanged_and_unknown_embedded_contract_refused(self):
        old,new,_=catalogs();a,b=old['tools'][-1],new['tools'][-1]
        row={'messages':[{'content':'사설 IP 조회'}],'tools':[]}
        self.assertEqual(refresh_row(row,a,b),(row,False))
        row['tools']=[{'function':{'name':TOOL,'description':'unreviewed','parameters':a['parameters']}}]
        with self.assertRaises(ValueError):refresh_row(row,a,b)


if __name__=='__main__':unittest.main()
