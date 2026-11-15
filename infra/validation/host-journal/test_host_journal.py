"""Fixed-host journal capability, scope and model grammar; no remote I/O."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT=Path(os.environ['SOC_HOST_JOURNAL_ROOT']).resolve()
sys.path.insert(0,str(ROOT/'infra/mcp'))

def load(name,rel):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

d=load('host_journal_core','infra/mcp/system_diagnostics.py')
h=load('host_journal_history','infra/mcp/diagnostic_history.py');h.core=d
j=load('host_journal_adapter','infra/mcp/diagnostic_journal.py');j.core=d
n=load('host_journal_native','infra/mcp/diagnostic_journal_native.py');n.core=d;n.journal=j
m=load('host_journal_mcp','infra/mcp/system-diagnostics-mcp.py');m._library=d
c=load('host_journal_contract','infra/hermes/chat_contract.py')
w=load('host_journal_gate','infra/hermes/soc_management_run.py')
from test_diagnostic_journal_native import FakeReader, event

NOW=1900000000
AT=h.shown(NOW*1000000)
NAME='mcp__system_diagnostics__get_system_diagnostics'

def args(target='b:systemd',**changes):
    return dict(target=target,view='journal',since_kst=h.shown((NOW-900)*1000000),
                until_kst=AT,**changes)

def catalog():
    return {'tools':[{'function':{'name':NAME,'parameters':m.tools()[0]['inputSchema']}}]}

class HostReader(FakeReader):
    def add_match(self,**fields):
        if 'PRIORITY' in fields and self.priorities is None:
            self.priorities=[]
        super().add_match(**fields)

class FixedHost(unittest.TestCase):
    def setUp(self):
        for name,value in (('_history',h),('_journal',j)):
            context=patch.object(d,name,value);context.start();self.addCleanup(context.stop)
        self.readers=[];self.flags=[]

    def factory(self,records):
        def create(*,system_only=False):
            self.flags.append(system_only);reader=HostReader(records);self.readers.append(reader);return reader
        return create

    def packet(self,records,value=None,host='b'):
        value=value or args()
        result=n.worker({'value':value,'host':host},now=NOW,factory=self.factory(records))
        return n.checked_packet(d.encode(result),value,host,NOW)

    def answer(self,records,value=None):
        value=value or args();packet=self.packet(records,value,value['target'][0])
        return j.finish(value,value['target'][0],NOW,packet['entries'],packet['source_limited'])

    def test_only_fixed_host_targets_gain_journal_not_metadata_history(self):
        for target in d.TARGETS:
            if isinstance(d.TARGETS[target],str):continue
            with self.subTest(target=target):
                if target in {'a:systemd','b:systemd','c:systemd'}:
                    self.assertEqual(j.request(args(target),NOW)[0],target)
                else:
                    with self.assertRaises(ValueError):j.request(args(target),NOW)
                value=args(target);value.pop('view')
                with self.assertRaises(ValueError):h.request(value,NOW)

    def test_untrusted_arguments_cannot_enable_or_widen_scope(self):
        for change in ({'host_journal':True},{'command':'id'},{'unit':'sshd.service'},
                       {'target':'d:systemd'},{'target':['b:systemd']},{'target':None},
                       {'path':'/var/log/journal'},{'view':'all'},{'journal_scope':'kernel'}):
            with self.subTest(change=change),self.assertRaises(ValueError):j.request(dict(args(),**change),NOW)

    def test_limits_and_time_validation_remain_shared(self):
        for change in ({'limit':True},{'limit':0},{'limit':51},{'limit':'50'},
                       {'since_kst':h.shown((NOW-86401)*1000000)},
                       {'since_kst':h.shown((NOW-31*86400)*1000000)},
                       {'until_kst':h.shown((NOW+1)*1000000)},
                       {'since_kst':AT},{'since_kst':'2030-03-18T01:00:00Z'}):
            with self.subTest(change=change),self.assertRaises(ValueError):j.request(dict(args(),**change),NOW)

    def test_native_reader_flags_keep_unit_source_and_exclude_user_aggregate(self):
        seen=[]
        binding=types.SimpleNamespace(__version__='235',LOCAL_ONLY=1,SYSTEM_ONLY=4,
                                      Reader=lambda **kw:seen.append(kw))
        with patch.dict(sys.modules,{'systemd':types.SimpleNamespace(journal=binding)}):
            n.reader_factory();n.reader_factory(system_only=True)
        self.assertEqual(seen,[{'flags':1},{'flags':5}])

    def test_all_hosts_can_read_unregistered_units_and_kernel_source(self):
        for host in 'abc':
            unknown=event(priority=b'3',unit='unregistered.service',cursor='unit')
            kernel=event(priority=b'3',cursor='kernel',_TRANSPORT=b'kernel');kernel['fields'].pop('_SYSTEMD_UNIT')
            result=self.answer([unknown,kernel],args(host+':systemd'))
            self.assertEqual(result['unit'],None);self.assertEqual(result['journal_target_scope'],'host_system')
            rows={r['source_transport']:r for r in result['entries']}
            self.assertEqual(rows[None]['source_units'],['unregistered.service'])
            self.assertEqual(rows['kernel']['source_units'],[])
            self.assertTrue(c.diagnostic_journal_fields(result)['journal_valid'])
        self.assertTrue(all(self.flags));self.assertTrue(all(r.closed for r in self.readers))

    def test_unit_path_shape_and_source_selection_are_unchanged(self):
        value=args('b:management')
        result=self.answer([event(priority=b'3'),event(priority=b'3',unit='other.service',cursor='other')],value)
        self.assertEqual(len(result['entries']),1)
        self.assertNotIn('journal_target_scope',result)
        self.assertNotIn('source_units',result['entries'][0]);self.assertEqual(self.flags,[False,False])

    def test_aggregate_error_selection_and_all_priorities(self):
        records=[event(priority=b'3',message=b'ordinary',cursor='severe'),
                 event(priority=b'6',message=b'RuntimeError: fixture',cursor='known'),
                 event(priority=b'6',message=b'ordinary',cursor='info'),
                 event(priority=b'7',message=b'ordinary',cursor='debug')]
        self.assertEqual(self.answer(records)['returned_entries'],2)
        self.assertEqual(self.answer(records,args(journal_scope='all'))['returned_entries'],4)

    def test_masking_happens_before_child_packet_and_identity_is_bounded(self):
        record=event(priority=b'3',message=b'password=DO_NOT_RETURN_THIS RuntimeError',
                     UNIT=b'other.service',OBJECT_SYSTEMD_UNIT=b'session-2.scope',_TRANSPORT=b'stdout')
        packet=self.packet([record]);self.assertNotIn(b'DO_NOT_RETURN_THIS',d.encode(packet))
        row=packet['entries'][0]
        self.assertEqual(row['source_units'],['capstone-management.service','other.service','session-2.scope'])
        self.assertEqual(row['message_state'],'redacted')
        for field,value in (('UNIT',b'bad unit'),('_TRANSPORT',b'bad\ntransport')):
            bad=copy.deepcopy(record);bad['fields'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.packet([bad])

    def test_host_mismatch_refused_before_native_reader(self):
        with self.assertRaises(ValueError):self.packet([],args('a:systemd'),'b')
        self.assertEqual(self.flags,[])

    def test_request_bound_scope_and_per_row_identity_survive_tamper_checks(self):
        result=self.answer([event(priority=b'3')])
        for change in ({'unit':'sshd.service'},{'journal_target_scope':'user'},
                       {'host':'a'},{'target':'a:systemd'}):
            bad=dict(result,**change)
            with self.subTest(change=change),self.assertRaises(ValueError):j.validate_answer(bad,args(),'b',NOW)
        for change in ({'source_units':['x.service']*2},{'source_units':['x.service']*4},
                       {'source_transport':'\n'},{'source_units':['/etc/shadow']}):
            bad=copy.deepcopy(result);bad['entries'][0].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):j.validate_answer(bad,args(),'b',NOW)
            self.assertFalse(c.diagnostic_journal_fields(bad)['journal_valid'])
        bad=copy.deepcopy(result);bad.pop('journal_target_scope')
        with self.assertRaises(ValueError):j.validate_answer(bad,args(),'b',NOW)
        self.assertFalse(c.diagnostic_journal_fields(bad)['journal_valid'])

    def test_cli_oracle_and_access_probe_use_system_not_unit_wildcards(self):
        calls=[]
        def run(argv,*a):calls.append(argv);return 0,b''
        result=j.answer(args(),'b',NOW,runner=run)
        with patch.object(d,'bounded_command',side_effect=run):n.access_check(args(),None,n.time.monotonic()+10)
        self.assertEqual(result['entries'],[])
        self.assertTrue(all('--system' in argv for argv in calls))
        self.assertTrue(all(not any(x.startswith('--unit') for x in argv) for argv in calls))
        self.assertFalse(result['journal_retention_verified']);self.assertIsNone(result['requested_window_total_count'])

    def test_schema_and_model_projection_are_equivalent_for_aggregate_scope(self):
        from jsonschema import Draft202012Validator
        schema=m.tools()[0]['inputSchema']
        with patch.object(w,'diagnostic_contract',return_value=c):projected=w.chat_read_schema(NAME,schema)
        self.assertIn('anyOf',projected)
        for target in d.TARGETS:
            for mode in ('current','history','journal'):
                value={'target':target} if mode=='current' else args(target)
                if mode=='history':value.pop('view')
                expected=(mode=='current' or isinstance(d.TARGETS[target],str)
                          or mode=='journal' and target in {'a:systemd','b:systemd','c:systemd'})
                with self.subTest(target=target,mode=mode):
                    self.assertEqual(Draft202012Validator(schema).is_valid(value),expected)
                    self.assertEqual(Draft202012Validator(projected).is_valid(value),expected)

    def test_short_host_questions_create_actual_journal_requirements(self):
        for host in 'ABC':
            for phrase in ('systemd 오류 로그 좀 봐줘','시스템 로그 보여줘','systemd 왜 실패했지?'):
                q=host+' '+phrase;plan=c.service_history_plan(catalog(),q,AT)
                with self.subTest(question=q):
                    self.assertIsNotNone(plan)
                    self.assertEqual(plan['units'],{host.lower()+':systemd':None})
                    requirements=plan['requirements'];self.assertEqual(len(requirements),1)
                    self.assertEqual(requirements[0]['arguments']['view'],'journal')
                    self.assertEqual(requirements[0]['arguments']['target'],host.lower()+':systemd')
                    self.assertTrue(c.service_history_state(plan,[])['pending'])

    def test_ambiguity_unknown_host_and_current_only_do_not_invent_history(self):
        for q in ('systemd 오류 로그 봐줘','시스템 로그 보여줘','D systemd 오류 로그 봐줘',
                  'A B systemd 오류 로그 봐줘','b:unknown 로그 봐줘','B systemd 현재 상태 보여줘'):
            with self.subTest(question=q):self.assertIsNone(c.service_history_plan(catalog(),q,AT))

    def test_old_catalog_preserves_unit_reads_without_host_journal_invention(self):
        req=catalog();schema=req['tools'][0]['function']['parameters']
        schema['properties']['target'].pop('x-capstone-host-journal-targets')
        schema['allOf'].pop()
        schema['allOf'][-1]['then']['properties']['target']['enum']=sorted(k for k,v in d.TARGETS.items() if isinstance(v,str))
        self.assertIsNone(c.service_history_plan(req,'B systemd 로그 봐줘',AT))
        self.assertIsNotNone(c.service_history_plan(req,'B vector 로그 봐줘',AT))

    def test_current_aggregate_and_historical_journal_are_separate_requirements(self):
        q='B systemd 어제 오류랑 지금 상태 봐줘';plan=c.service_history_plan(catalog(),q,AT)
        requirements=plan['requirements'];self.assertEqual(len(requirements),2)
        self.assertEqual(requirements[0]['arguments'],{'target':'b:systemd'})
        self.assertEqual(requirements[1]['arguments']['view'],'journal')
        self.assertIn(':journal:not_read',c.service_history_state(plan,[])['incomplete'][1])

    def test_real_journal_receipts_complete_reads_not_health_or_attribution(self):
        q='B systemd 오류 로그 봐줘';plan=c.service_history_plan(catalog(),q,AT)
        value=plan['requirements'][0]['arguments'];result=self.answer([event(priority=b'3')],value)
        receipt={**plan['requirements'][0],'is_error':False,'data':result}
        now=c._diagnostic_instant(AT)
        self.assertEqual(c.service_history_state(plan,[receipt],now)['incomplete'],[])
        context=c.service_report_context(catalog(),q,AT,[receipt],now=now)
        self.assertEqual(context['requested_service_scope']['aggregate_targets'],{'b:systemd':'host_system'})
        bad=copy.deepcopy(receipt);bad['data']['journal_target_scope']='unit'
        self.assertTrue(c.service_history_state(plan,[bad],now)['incomplete'])

    def test_display_preserves_same_message_from_different_source_units(self):
        rows=[event(priority=b'3',unit='one.service',cursor='one'),
              event(priority=b'3',unit='two.service',cursor='two')]
        result=self.answer(rows);fields=c.diagnostic_journal_fields(result)
        rendered=c.diagnostic_evidence_rows(dict(fields,target='b:systemd',
            observed_at_kst=AT,requested_since_kst=args()['since_kst'],requested_until_kst=AT),str)
        self.assertEqual(len(rendered),3)
        self.assertIn('호스트 시스템 journal',rendered[0][2])
        self.assertTrue(any('one.service' in r[2] for r in rendered))
        self.assertTrue(any('two.service' in r[2] for r in rendered))

    def test_extension_catalog_drift_is_not_silently_accepted(self):
        for kind in ('host','scope','target','metadata','union'):
            req=catalog();schema=req['tools'][0]['function']['parameters']
            ext=schema['properties']['target']['x-capstone-host-journal-targets']
            if kind=='host':ext['b:systemd']['host']='a'
            elif kind=='scope':ext['b:systemd']['scope']='user'
            elif kind=='target':ext['b:collection']=ext.pop('b:systemd')
            elif kind=='metadata':schema['allOf'][-1]['then']['properties']['target']['enum'].pop()
            else:schema['allOf'][-2]['then']['properties']['target']['enum'].pop()
            with self.subTest(kind=kind):self.assertIsNone(c.service_history_plan(req,'B systemd 오류 로그',AT))

if __name__=='__main__':unittest.main()
