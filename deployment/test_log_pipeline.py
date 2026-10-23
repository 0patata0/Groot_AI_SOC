#!/usr/bin/env python3
"""Local pure/render/failure-contract tests; no Docker/SSH/services/network."""
import copy
import importlib.util
import json
import os
import stat
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('log_pipeline',HERE/'log_pipeline.py')
lp=importlib.util.module_from_spec(spec); spec.loader.exec_module(lp)
FILES=lp.source_files(HERE.parent,False)
ENV={'SECURITY_HOST':'192.0.2.10','SIEM_HOST':'192.0.2.11','SERVICE_HOST':'192.0.2.12'}
CONFIG={**lp.settings('security',ENV),'machine_id':'a'*32,'docker':'/usr/bin/docker',
        'vector':'/usr/bin/vector','binding':'b'*64}


class Pipeline(unittest.TestCase):
    def test_source_fingerprint_binds_adapter(self):
        first=lp.fingerprint(FILES); changed=dict(FILES)
        changed['deployment/log_pipeline.py']+=b'\n'
        self.assertNotEqual(first['source_sha256'],lp.fingerprint(changed)['source_sha256'])

    def test_settings_independent_parent_profile(self):
        self.assertEqual(lp.settings('security',ENV),lp.settings('security',{**ENV,'PROFILE':'f'*64}))

    def test_admin_block_exemptions_do_not_filter_logs(self):
        self.assertEqual(lp.settings('security',ENV),lp.settings('security',{**ENV,'ADMIN_PROTECTED_CIDRS':'203.0.113.0/24'}))

    def test_settings_missing_addresses(self):
        with self.assertRaises(lp.Refused):lp.settings('security',{})

    def test_settings_duplicate_hosts(self):
        with self.assertRaises(lp.Refused):lp.settings('security',{**ENV,'SIEM_HOST':ENV['SECURITY_HOST']})

    def test_settings_reject_shell_address(self):
        with self.assertRaises(lp.Refused):lp.settings('security',{**ENV,'LOG_PROTECTED_IPS':'$(id)'})

    def test_protected_management_addresses_required(self):
        with self.assertRaises(lp.Refused):lp.settings('security',{**ENV,'LOG_PROTECTED_IPS':'198.51.100.1'})

    def test_fixed_role_path(self):
        with self.assertRaises(lp.Refused):lp.settings('security',{**ENV,'ROLE_DIR':'/tmp/elsewhere'})

    def test_duplicate_json_rejected(self):
        with self.assertRaises(lp.Refused):lp.parse('{"schema":1,"schema":2}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(lp.Refused):lp.parse('{"x":NaN}')

    def test_runtime_no_live_site_identifiers(self):
        rendered=lp.render_runtime(FILES,CONFIG)
        for raw in rendered.values():
            for marker in (lp.MID,lp.OLD_LOG,'groot-sec','211.170.162.110','211.170.162.111'):
                self.assertNotIn(marker.encode(),raw)
        self.assertIn(b'capstone-security-suricata',rendered[str(lp.RUNTIME/'writer-gates.sh')])

    def test_rendered_bash_syntax(self):
        for path,raw in lp.render_runtime(FILES,CONFIG).items():
            if raw.startswith((b'#!/bin/bash',b'#! /bin/bash')):
                p=subprocess.run(['/bin/bash','-n'],input=raw,capture_output=True)
                self.assertEqual(p.returncode,0,path+':'+p.stderr.decode())

    def test_history_hashes_follow_rendered_bytes(self):
        output=lp.render_runtime(FILES,CONFIG); base='/usr/local/lib/capstone-vector-history-auto/'
        rows=output[base+'runtime.sha256'].decode().splitlines();self.assertEqual(len(rows),8)
        for row in rows:
            digest,name=row.split();self.assertEqual(digest,lp.sha(output[base+name]))

    def test_native_config_modes_are_exact(self):
        for name in ('vector.toml','vector.env','raw-line-binding.json'):
            self.assertEqual(lp.runtime_mode(str(lp.CFG/name)),0o600)
        self.assertEqual(lp.runtime_mode(str(lp.RUNTIME/'coordinator.sh')),0o400)

    def test_only_fixed_writer_parents_allow_nonroot(self):
        def metadata(uid,mode=0o755):return types.SimpleNamespace(st_mode=stat.S_IFDIR|mode,st_uid=uid,st_gid=uid)
        self.assertTrue(lp.trusted_directory('/opt/capstone/security/logs/modsecurity',metadata(101)))
        self.assertTrue(lp.trusted_directory('/opt/capstone/security/logs/suricata',metadata(998)))
        for path,uid,mode in [('/opt/capstone/security/logs/modsecurity',998,0o755),
            ('/opt/capstone/security/logs/modsecurity',101,0o775),('/tmp/writer',101,0o755),
            ('/opt/capstone/security/logs/modsecurity/capstone-managed',101,0o711)]:
            self.assertFalse(lp.trusted_directory(path,metadata(uid,mode)))

    def test_native_wazuh_parent_exception_is_explicit(self):
        import grp
        info=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o770,st_uid=0,st_gid=123)
        with patch.object(grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=123)):
            self.assertTrue(lp.trusted_directory('/var/ossec/etc',info,True))
            self.assertFalse(lp.trusted_directory('/var/ossec/etc',info))
            self.assertFalse(lp.trusted_directory('/etc/elsewhere',info,True))

    def test_auxiliary_retention_excludes_raw(self):
        output=lp.render_runtime(FILES,CONFIG)
        policy=output[str(lp.CFG/'auxiliary-logrotate.conf')]
        for bad in (b'eve.json',b'audit.log',b'generation-',b'*'):self.assertNotIn(bad,policy)
        for good in (b'fast.log',b'stats.log',b'suricata.log',b'capstone-access.log',b'rotate 14',b'maxsize 500M'):
            self.assertIn(good,policy)

    def test_native_rule_and_fixtures_current_addresses(self):
        rule=lp.rule_config(FILES[lp.W+'capstone_vector_rules.xml'],CONFIG)
        self.assertNotIn(rb'211\.170\.162',rule)
        for address in CONFIG['protected_ips']:
            self.assertEqual(rule.count(address.replace('.',r'\.').encode()),4)
        output=lp.native_logtest_files(FILES,CONFIG,'f'*64)
        self.assertEqual(len(lp.fixture_rows(output['fixtures/correlation/expected.tsv'])),24)
        self.assertEqual(len(lp.fixture_rows(output['fixtures/evidence/expected.tsv'])),53)
        self.assertIn(b'192.0.2.10',output['fixtures/evidence/protected-source.jsonl'])
        for script in lp.LOGTESTS:
            raw=output['tests/'+script]
            self.assertIn(b'--host unix:///var/run/docker.sock exec',raw)
            self.assertNotIn(b'groot-sec',raw)
            self.assertEqual(subprocess.run(['/bin/sh','-n'],input=raw,capture_output=True).returncode,0)

    def test_fixture_manifest_rejects_traversal(self):
        with self.assertRaises(lp.Refused):lp.fixture_rows(b'../../bad|evidence|reject\n')

    def test_native_positive_fixture_survives_documentation_range_hosts(self):
        config=copy.deepcopy(CONFIG);config['protected_ips']+=['192.0.2.40','198.51.100.20']
        output=lp.native_logtest_files(FILES,config,'f'*64)
        norm=lp.parse(output['fixtures/evidence/suricata.jsonl'])['capstone_norm']
        self.assertNotIn(norm['source_ip'],config['protected_ips'])
        self.assertNotIn(norm['destination_ip'],config['protected_ips'])

    def test_runtime_docker_context_is_not_used(self):
        output=lp.render_runtime(FILES,CONFIG)
        body=output[str(lp.RUNTIME/'coordinator.sh')]
        self.assertEqual(body.count(b'/usr/bin/docker --host unix:///var/run/docker.sock'),3)
        self.assertIn(b'--host unix:///var/run/docker.sock',output[str(lp.RUNTIME/'writer-gates.sh')])

    def test_first_start_preserves_native_guard(self):
        body=lp.render_runtime(FILES,CONFIG)[str(lp.RUNTIME/'coordinator.sh')].decode()
        self.assertIn('result=$(cg_wazuh_cold',body)
        self.assertIn('result=$(cg_vector_current',body)
        self.assertIn('.expires_at>$now',body)
        self.assertIn('.phase=="sealed" and $size==0',body)
        self.assertIn('initial_native_checkpoint', (HERE/'log_pipeline.py').read_text())
        self.assertNotIn('echo >',body)

    def test_yaml_only_expected_filename_changed(self):
        source=b'outputs:\n  - eve-log:\n      enabled: yes\n      filename: eve.json\n'
        self.assertEqual(lp.suricata_config(source),source.replace(b'eve.json',b'capstone-managed/active.jsonl'))
        with self.assertRaises(lp.Refused):lp.suricata_config(source+source)

    def test_agent_config_preserves_raw_and_AR(self):
        original=b'<ossec_config><client><disable-active-response>no</disable-active-response></client><localfile><location>/raw/eve.json</location><log_format>json</log_format></localfile></ossec_config>\n'
        result=lp.agent_configuration(original,FILES[lp.W+'agent-localfile.xml'])
        self.assertTrue(result.startswith(original));self.assertEqual(result.count(b'/raw/eve.json'),1)
        self.assertIn(b'<disable-active-response>no</disable-active-response>',result)
        with self.assertRaises(lp.Refused):lp.agent_configuration(result,FILES[lp.W+'agent-localfile.xml'])

    def test_agent_DTD_rejected(self):
        with self.assertRaises(lp.Refused):lp.agent_configuration(b'<!DOCTYPE x><ossec_config/>',b'')

    def test_compose_explicit_mounts_no_generated_RO_target(self):
        original={'services':{'waf':{'container_name':'capstone-security-waf','volumes':[]},
                    'suricata':{'container_name':'capstone-security-suricata','volumes':[],'command':['-i','ens18']}}}
        result=lp.security_compose(original,Path('/opt/capstone/security'))
        self.assertEqual(original['services']['suricata']['command'],['-i','ens18'])
        self.assertEqual(result['services']['suricata']['command'][-2:],['-i','ens18'])
        targets=[v['target'] for v in result['services']['waf']['volumes']]
        self.assertIn('/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template',targets)
        self.assertNotIn('/etc/modsecurity.d/modsecurity-override.conf',targets)
        for svc in result['services'].values():
            for mount in svc['volumes']:self.assertFalse(mount['bind']['create_host_path'])

    def test_mount_conflict_rejected(self):
        value={'volumes':['/a:/target:ro']}
        with self.assertRaises(lp.Refused):lp.add_mount(value,'/b','/target')

    def test_container_extra_mount_rejected(self):
        image={'Config':{'Cmd':['x'],'Entrypoint':['e'],'Env':['TZ=UTC']}}
        expected={'image':'sha256:'+'a'*64,'volumes':['/a:/target:ro'],'environment':{'TZ':'Asia/Seoul'}}
        actual={'Image':expected['image'],'Config':{'Cmd':['x'],'Entrypoint':['e'],'Env':['TZ=Asia/Seoul']},
                'Mounts':[{'Type':'bind','Source':'/a','Destination':'/target','RW':False}]}
        lp.compare_container(actual,expected,image,{},'capstone-security')
        for change in ('mount','command','environment','readonly'):
            item=copy.deepcopy(actual)
            if change=='mount':item['Mounts'].append({'Type':'bind','Source':'/','Destination':'/host','RW':True})
            elif change=='command':item['Config']['Cmd']=['sh']
            elif change=='environment':item['Config']['Env'].append('LD_PRELOAD=bad')
            else:item['Mounts'][0]['RW']=True
            with self.subTest(change=change),self.assertRaises(lp.Refused):lp.compare_container(item,expected,image,{},'capstone-security')

    def test_monitor_identity_protection_no_actions(self):
        value=lp.monitor_candidate(FILES[lp.W+'indexer-native/window-v2/monitor.json'],'023',CONFIG['protected_ips'])
        text=json.dumps(value)
        self.assertIn('023',text);self.assertNotIn('"001"',text);self.assertNotIn('211.170.162.',text)
        self.assertTrue(all(t['query_level_trigger']['actions']==[] for t in value['triggers']))
        lp.compare_monitor(value,value,False,FILES[lp.W+'indexer-native/deploy-monitor-b.py'])

    def test_monitor_server_expansion_and_actions(self):
        expected=lp.monitor_candidate(FILES[lp.W+'indexer-native/window-v2/monitor.json'],'123',CONFIG['protected_ips'])
        actual=copy.deepcopy(expected);query=actual['inputs'][0]['search']['query']
        query['query']['bool']['adjust_pure_negative']=True
        query['query']['bool']['boost']=1.0
        query['query']['bool']['filter'][0]['term']['agent.id']={'value':'123','boost':1.0}
        for script in query['aggs']['observation']['scripted_metric'].values():
            if isinstance(script,dict) and 'source' in script:script.setdefault('params',{})
        lp.compare_monitor(actual,expected,False,FILES[lp.W+'indexer-native/deploy-monitor-b.py'])
        actual['triggers'][0]['query_level_trigger']['actions']=[{'destination_id':'unexpected'}]
        with self.assertRaises(lp.Refused):lp.compare_monitor(actual,expected,False,FILES[lp.W+'indexer-native/deploy-monitor-b.py'])

    def test_monitor_search_requires_complete_results(self):
        result={'timed_out':False,'_shards':{'failed':0,'total':1,'successful':1},
                'hits':{'total':{'value':0,'relation':'eq'},'hits':[]}}
        self.assertEqual(lp.exact_monitor_ids(lambda *a,**k:(200,result)),[])
        for field in ('timeout','partial','inexact'):
            value=copy.deepcopy(result)
            if field=='timeout':value['timed_out']=True
            elif field=='partial':value['_shards']['successful']=0
            else:value['hits']['total']['relation']='gte'
            with self.assertRaises(lp.Refused):lp.exact_monitor_ids(lambda *a,**k:(200,value))

    def test_monitor_missing_index_is_narrow(self):
        value={'error':{'type':'index_not_found_exception','index':'.opendistro-alerting-config'}}
        self.assertEqual(lp.exact_monitor_ids(lambda *a,**k:(404,value)),[])
        value['error']['index']='some-other-index'
        with self.assertRaises(lp.Refused):lp.exact_monitor_ids(lambda *a,**k:(404,value))

    def test_initial_state_not_ack(self):
        pins={k:'b'*64 for k in ('container_id','engine_config_sha256','producer_format_sha256','vector_config_sha256','vector_env_sha256','wazuh_config_sha256')}
        state=lp.state_initial(CONFIG,'suricata',types.SimpleNamespace(st_dev=7,st_ino=42),pins,'c'*64,'d'*32)
        self.assertEqual(state['current']['number'],0);self.assertIsNone(state['proof']['readers_drained'])
        self.assertIsNone(state['pending']);self.assertEqual(state['machine_id'],'a'*32)
        with self.assertRaises(lp.Refused):lp.state_initial(CONFIG,'suricata',types.SimpleNamespace(st_dev=7,st_ino=42),{},'c'*64,'d'*32)

    def test_partial_install_not_retried(self):
        item=object.__new__(lp.Bootstrap);item.role='security'
        with patch.object(item,'current',return_value={'phase':'activation_pending'}):
            with self.assertRaises(lp.Refused):item.activate()

    def test_complete_apply_only_verifies(self):
        item=object.__new__(lp.Bootstrap);item.role='security'
        with patch.object(item,'current',return_value={'phase':'complete'}),patch.object(item,'verify',return_value={'status':'verified'}) as check:
            self.assertEqual(item.activate(),{'status':'verified'});check.assert_called_once()

    def test_completed_check_is_read_only(self):
        item=object.__new__(lp.Bootstrap);item.receipt=types.SimpleNamespace(exists=lambda:True)
        item.fp={'source_sha256':'a'*64}
        for phase in ('prepared','rules_active','complete'):
            with patch.object(item,'current',return_value={'phase':phase,'files':{'/exact':'b'*64}}),patch.object(lp,'read',return_value=b'x'),patch.object(lp,'sha',return_value='b'*64),patch.object(lp,'run') as command:
                self.assertEqual(item.check()['mutations'],0);command.assert_not_called()

    def test_profile_or_receipt_tamper_rejected(self):
        item=object.__new__(lp.Bootstrap);item.receipt=Path('/fake/receipt');item.config_hash='a'*64;item.fp={}
        with patch.object(lp,'read',return_value=lp.canonical({'schema':1,'config_sha256':'b'*64,'sources':{}})):
            with self.assertRaises(lp.Refused):item.current()

    def test_unsafe_source_path_rejected(self):
        with self.assertRaises(lp.Refused):lp.read(Path('relative'))
        with tempfile.TemporaryDirectory(prefix='capstone-log-test-') as tmp:
            p=Path(tmp)/'link';p.symlink_to('/etc/hosts')
            with self.assertRaises((lp.Refused,OSError)):lp.read(p)

    def test_indexer_redirect_and_scope_rejected(self):
        with self.assertRaises(lp.Refused):lp.NoRedirect().redirect_request(None,None,None,None,None,None)
        obj=object.__new__(lp.Indexer);obj.base='https://192.0.2.1:9200'
        with self.assertRaises(lp.Refused):obj('DELETE','/_all')


if __name__=='__main__':unittest.main()
