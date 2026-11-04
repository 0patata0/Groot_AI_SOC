"""Web evidence privacy, scope, transport and failure contracts; no live calls."""
from datetime import datetime,timedelta
import copy
import gzip
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock

HERE=Path(__file__).resolve().parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
w=load('tested_web_evidence','web_evidence.py')
r=load('tested_web_reader','read-web-evidence.py')
c=load('tested_web_client','web_evidence_client.py')
AT=datetime.fromisoformat('2026-11-04T18:00:00+09:00')


def line(path='/dvwa/login.php?id=secret-token',stamp='04/Nov/2026:08:58:00 +0000',ip='192.0.2.40',status=200):
    return (f'{ip} - private-user [{stamp}] "GET {path} HTTP/1.1" {status} 421 "https://private.invalid/?password=hidden" "private-agent"\n').encode()


def snapshot(rows=()):
    return {'schema':1,'host':'c','checked_at':int(AT.timestamp()),'expires_at':int(AT.timestamp())+w.TTL,'retained_seconds':w.HISTORY,
        'agent':{'id':'002','name':'test-web'},'apache_unit':{'LoadState':'loaded','ActiveState':'active','SubState':'running'},
        'configuration':{'files':[],'standard_access_log_configured':True,'configuration_sha256':'a'*64,'targets':{
            target:{'backend_role':'c','request_path_prefix':prefix,'configured_in_file_snapshot':True,'diagnostic_target':'c:apache',
                    'frontend_binding_verified':False,'runtime_configuration_load_verified':False} for target,prefix in w.TARGETS.items()}},
        'coverage':{'bytes_scanned':200,'malformed_lines':0,'files_unavailable':0,'scan_limited':False,'rows_truncated':False,'logging_continuity_verified':False},
        'files':[{'name':'access.log','inode':1,'size_at_open':200,'decompressed_bytes_scanned':200,'decompressed_prefix_sha256':'b'*64,'changed_during_read':False}],
        'records':list(rows)}


def query(**extra):
    return {'operation':'search_web_access','arguments':{'target':'c:dvwa','since_kst':'2026-11-04T17:57:00+09:00',
        'until_kst':'2026-11-04T17:59:00+09:00',**extra}}


class Projection(unittest.TestCase):
    def test_private_user_query_referrer_agent_and_absolute_uri_credentials_never_return(self):
        row=w.parse_access(line('http://api-user:api-secret@example.invalid/dvwa/login.php?password=very-secret'),'access.log')
        data=json.dumps(row)
        for value in ('api-user','api-secret','private-user','very-secret','password=','private.invalid','private-agent'):
            self.assertNotIn(value,data)
        self.assertEqual(row['path'],'/dvwa/login.php');self.assertTrue(row['query_present'])
        self.assertEqual(row['timestamp_kst'],'2026-11-04T17:58:00+09:00')

    def test_identical_lines_are_not_assumed_to_be_one_http_transaction(self):
        row=w.parse_access(line(),'access.log');view=w.answer(query(),snapshot([row,row]),AT)
        self.assertEqual(view['returned_count'],2)
        self.assertEqual(view['identity_scope'],'log_line_bytes_not_unique_http_transaction')
        self.assertIsNone(view['actual_request_total_count'])

    def test_service_and_source_filters_do_not_mix_other_sites_or_clients(self):
        rows=[w.parse_access(line(path=p,ip=ip),'access.log') for p,ip in [('/dvwa/x','192.0.2.40'),('/dvwaX/x','192.0.2.40'),('/_offline-labs/api/status','192.0.2.40'),('/dvwa/x','192.0.2.41')]]
        view=w.answer(query(source_ip='192.0.2.40'),snapshot(rows),AT)
        self.assertEqual(view['returned_count'],1);self.assertEqual(view['records'][0]['source_ip'],'192.0.2.40')

    def test_caps_zero_and_missing_logging_continuity_remain_explicit(self):
        row=w.parse_access(line(),'access.log');view=w.answer(query(limit=1),snapshot([row,row]),AT)
        self.assertEqual((view['returned_count'],view['retained_index_match_count']),(1,2))
        self.assertTrue(view['returned_rows_truncated']);self.assertFalse(view['logging_continuity_verified'])
        empty=w.answer(query(),snapshot(),AT);self.assertEqual(empty['returned_count'],0);self.assertIsNone(empty['actual_request_total_count'])

    def test_service_configuration_and_process_state_are_not_app_or_frontend_health(self):
        view=w.answer({'operation':'get_web_service_target','arguments':{'target':'c:lab-java'}},snapshot(),AT)
        self.assertFalse(view['service']['frontend_binding_verified']);self.assertFalse(view['service']['runtime_configuration_load_verified'])
        self.assertNotIn('records',view);self.assertFalse(view['mutation_performed'])

    def test_recent_window_is_calculated_once_without_model_time_arithmetic(self):
        args={'operation':'search_web_access','arguments':{'target':'c:dvwa','lookback_minutes':60}}
        normalized=w.request(args,AT)
        self.assertEqual(normalized['arguments']['since_kst'],'2026-11-04T17:00:00+09:00')
        self.assertEqual(normalized['arguments']['until_kst'],'2026-11-04T18:00:00+09:00')
        self.assertNotIn('lookback_minutes',normalized['arguments'])
        self.assertIn('lookback_minutes',args['arguments'])
        with self.assertRaises(ValueError):w.request(query(lookback_minutes=60),AT)

    def test_malformed_or_unaddressable_log_rows_do_not_become_valid_requests(self):
        for raw in (b'not a log\n',line(ip='not-an-ip'),line(stamp='not-a-time'),line(path='/bad path'),line(status=999)):
            with self.subTest(raw=raw[:20]):self.assertIsNone(w.parse_access(raw,'access.log'))


class Boundaries(unittest.TestCase):
    def test_wazuh_registration_directory_exception_never_applies_to_other_files(self):
        meta=SimpleNamespace(st_mode=stat.S_IFDIR|0o770,st_uid=112,st_gid=112)
        with patch.object(w.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=112)),patch.object(w.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=112)):
            w.safe_directory(w.CLIENT_KEYS.parent,meta,registration=True)
            for path,registration in ((w.CLIENT_KEYS.parent,False),(Path('/var/ossec'),True),(Path('/etc'),True)):
                with self.subTest(path=path,registration=registration),self.assertRaises(ValueError):w.safe_directory(path,meta,registration=registration)

    def test_only_exact_distro_log_ancestor_allows_syslog_group_write(self):
        meta=SimpleNamespace(st_mode=stat.S_IFDIR|0o775,st_uid=0,st_gid=104)
        with patch.object(w.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=104)):
            w.safe_directory(Path('/var/log'),meta,True)
            for path,log_path in ((Path('/var/log'),False),(Path('/var/log/apache2'),True),(Path('/var/lib'),True)):
                with self.subTest(path=path,log_path=log_path),self.assertRaises(ValueError):w.safe_directory(path,meta,log_path)
            with self.assertRaises(ValueError):w.safe_directory(Path('/var/log'),SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0,st_gid=104),True)

    def test_no_file_shell_host_or_unregistered_target_arguments(self):
        for extra in ({'path':'/etc/shadow'},{'command':'id'},{'host':'127.0.0.1'},{'target':'c:unknown'},
                      {'source_ip':'192.0.2.40; id'},{'limit':51},{'limit':True}):
            with self.subTest(extra=extra),self.assertRaises(ValueError):w.request(query(**extra),AT)
        with self.assertRaises(ValueError):w.request({'operation':'collect','arguments':{'target':'c:dvwa'}},AT)

    def test_timezones_future_oversized_and_unretained_intervals_refused(self):
        for extra in ({'since_kst':'2026-11-04T08:00:00Z'},{'until_kst':'2026-11-05T00:00:00+09:00'},
                      {'since_kst':'2026-11-02T17:00:00+09:00'},{'since_kst':'2026-10-01T00:00:00+09:00'},
                      {'since_kst':'2026-11-04T17:59:00+09:00'}):
            with self.subTest(extra=extra),self.assertRaises(ValueError):w.request(query(**extra),AT)

    def test_stale_snapshot_cannot_look_like_an_empty_success(self):
        with self.assertRaises(ValueError):w.answer(query(),snapshot(),AT+timedelta(seconds=w.TTL+1))

    def test_snapshot_rejects_raw_fields_and_false_frontend_attestation(self):
        row=w.parse_access(line(),'access.log')
        bad=snapshot([dict(row,raw='private')])
        with self.assertRaises(ValueError):w.validate(bad,int(AT.timestamp()))
        bad=snapshot();bad['configuration']['targets']['c:dvwa']['frontend_binding_verified']=True
        with self.assertRaises(ValueError):w.validate(bad,int(AT.timestamp()))

    def test_original_commands_and_cli_arguments_refused_before_loading_code(self):
        for argv,command in ((['reader','/tmp/file'],''),(['reader'],'cat /etc/shadow')):
            with patch.object(r.sys,'argv',argv),patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':command}),patch.object(r,'library') as library:
                with self.assertRaises(ValueError):r.main()
                library.assert_not_called()

    def test_reader_input_is_bounded_and_duplicate_json_is_rejected(self):
        for data in (b'',b'x'*4097):
            a,b=os.pipe();os.write(b,data);os.close(b)
            try:
                with patch.object(r.sys,'stdin',SimpleNamespace(fileno=lambda:a)),self.assertRaises(ValueError):r.incoming()
            finally:os.close(a)
        with self.assertRaises(ValueError):json.loads('{"operation":"a","operation":"b"}',object_pairs_hook=w.unique)


class Collection(unittest.TestCase):
    def collect_fixture(self,logs):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,data in logs.items():(root/name).write_bytes(data)
            def open_file(path,maximum):return open(path,'rb'),path.stat()
            with patch.object(w,'LOGS',root),patch.object(w,'parents'),patch.object(w,'root_open',side_effect=open_file),patch.object(w.os,'geteuid',return_value=0),patch.object(w,'configuration',return_value=snapshot()['configuration']),patch.object(w,'agent_identity',return_value=snapshot()['agent']),patch.object(w.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=active\nSubState=running\n')):
                return w.collect(int(AT.timestamp()))

    def test_current_and_rotated_gzip_rows_keep_source_provenance(self):
        value=self.collect_fixture({'access.log':line(), 'access.log.1.gz':gzip.compress(line('/dvwa/previous.php')),'error.log':b'not access'})
        self.assertEqual(len(value['records']),2);self.assertEqual(len(value['files']),2)
        self.assertFalse(value['coverage']['scan_limited']);w.validate(value,int(AT.timestamp()))

    def test_bad_gzip_does_not_publish_its_unverified_prefix_rows(self):
        compressed=gzip.compress(line('/dvwa/bad.php'));compressed=compressed[:-8]+b'invalid!'
        value=self.collect_fixture({'access.log':line(), 'access.log.1.gz':compressed})
        self.assertEqual(value['coverage']['files_unavailable'],1);self.assertTrue(value['coverage']['scan_limited'])
        self.assertEqual(len(value['records']),1);self.assertNotIn('/dvwa/bad.php',json.dumps(value))

    def test_source_byte_cap_reports_partial_coverage(self):
        with patch.object(w,'MAX_INPUT',100):value=self.collect_fixture({'access.log':line()*5})
        self.assertTrue(value['coverage']['scan_limited']);self.assertLessEqual(value['coverage']['bytes_scanned'],100)


class Client(unittest.TestCase):
    def test_transport_reuses_fixed_identity_and_never_accepts_remote_commands(self):
        core=HERE/'web_evidence.py'
        d=SimpleNamespace(root_file=lambda path,maximum:core.read_bytes(),parsed=json.loads,bounded_command=Mock(return_value=(0,json.dumps({
            'source':'c_apache_access_snapshot','target':'c:dvwa','mutation_performed':False,'untrusted_evidence':True}).encode())))
        server=SimpleNamespace(route_config=lambda:{'hosts':{'a':'192.0.2.1','c':'192.0.2.2'},'ssh_port':22},library=lambda:d,KNOWN_HOSTS='/fixed/known',IDENTITY='/fixed/key')
        with patch.object(c,'diagnostics',return_value=server):c.call('get_web_service_target',{'target':'c:dvwa'})
        args,kwargs=d.bounded_command.call_args;command=args[0]
        self.assertEqual(command[-1],'capstone-web-evidence@192.0.2.2');self.assertIn('StrictHostKeyChecking=yes',command)
        self.assertIn('/fixed/key',command);self.assertNotIn('sudo',command)
        self.assertEqual(json.loads(kwargs['input_data']),{'operation':'get_web_service_target','arguments':{'target':'c:dvwa'}})


if __name__=='__main__':unittest.main()
