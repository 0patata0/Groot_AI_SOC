"""Inventory bounds, freshness, scope and fixed-command contracts; no host reads."""
import copy
import importlib.util
import json
from pathlib import Path
import types
import unittest
import os
import tempfile
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


d = load('system_diagnostics'); h = load('host_inventory')
h.core = d
NOW = 1900000000


def snap():
    v = {'schema': 1, 'host': 'a', 'views': {name: {'status': 'observed', 'reason': None,
         'observed_at': NOW, 'rows': []} for name in h.VIEWS}}
    v['views']['services']['rows'] = [dict(unit='a.service', load='loaded', active='active', sub='running'),
        dict(unit='b.service', load='loaded', active='failed', sub='failed'),
        dict(unit='c.service', load='loaded', active='active', sub='exited')]
    v['views']['containers']['rows'] = [dict(id='a', name='app', image='test', state='running', status='Up')]
    return v


class Inventory(unittest.TestCase):
    def test_resolved_dns_is_data_only_and_not_required_to_be_root_owned_code(self):
        with tempfile.NamedTemporaryFile() as file:
            file.write(b'nameserver 127.0.0.53\nsearch internal.example\n');file.flush();file.seek(0)
            with patch.object(Path,'resolve',return_value=Path('/run/systemd/resolve/stub-resolv.conf')), \
                 patch.object(h.os,'open',return_value=os.dup(file.fileno())):
                rows=h.collect_view('network',lambda *args:(0,b'[]'),'/usr/bin/docker')
            self.assertEqual(rows,[dict(category='dns',name='nameserver',value='127.0.0.53')])

    def test_docker_inspect_allowlist_excludes_env_command_health_output_and_labels(self):
        ident='a'*64;secret='FORBIDDEN_SECRET';catalog=json.dumps(dict(ID=ident,Names='app',Image='img',State='running',Status='Up')).encode()
        item=dict(Id=ident,Image='sha256:image',Config={'Image':'img','Env':[secret],'Cmd':[secret],'Labels':{'secret':secret}},
                  RestartCount=2,State=dict(Status='running',Running=True,Paused=False,Restarting=False,OOMKilled=False,
                  ExitCode=0,Error=secret,StartedAt='2026-11-08T00:00:00Z',FinishedAt='0001-01-01T00:00:00Z',
                  Health={'Status':'healthy','FailingStreak':0,'Log':[{'Output':secret}]}),
                  HostConfig=dict(RestartPolicy={'Name':'unless-stopped'},NetworkMode='bridge',Privileged=False,
                  ReadonlyRootfs=True,Memory=1000,NanoCpus=0,LogConfig={'Type':'json-file','Config':{'secret':secret}}),
                  NetworkSettings={'Ports':{'80/tcp':[{'HostIp':'127.0.0.1','HostPort':'8080'}]},'Networks':{}},Mounts=[])
        def run(argv,*args):return (0,catalog) if 'ps' in argv else (0,json.dumps([item]).encode())
        rows=h.docker_view('container_details',run,'/usr/bin/docker');self.assertNotIn(secret,str(rows))
        self.assertIn({'name':'app','field':'restart_count','value':'2'},rows)
        self.assertTrue(any(row['field']=='port:80/tcp' for row in rows))

    def test_detail_scope_requires_exact_object_and_never_accepts_exec_or_paths(self):
        for value in (dict(host='a',view='container_details'), dict(host='a',view='service_details'),
                      dict(host='a',view='container_logs',container='--privileged'),
                      dict(host='a',view='container_details',container='../shadow'),
                      dict(host='a',view='service_details',unit='/etc/shadow'),
                      dict(host='a',view='services',unit='ssh.service')):
            with self.subTest(value=value),self.assertRaises(ValueError):h.request(value)
        h.request(dict(host='all',view='container_details',container='hermes'))
        h.request(dict(host='a',view='service_details',unit='ssh.service'))

    def test_docker_logs_mask_both_streams_and_keep_failure_distinct(self):
        j=load('diagnostic_journal');j.core=d
        ident='a'*64;catalog=json.dumps(dict(ID=ident,Names='app',Image='img',State='running',Status='Up')).encode()
        seen=[]
        def run(argv,bound,seconds,**kwargs):
            seen.append((argv,kwargs))
            if 'ps' in argv:return 0,catalog
            self.assertEqual(kwargs,{'docker_logs':True});self.assertEqual(argv[-2:],['--',ident]);self.assertLessEqual(seconds,2)
            return 0,b'2026-11-08T01:00:00.123456789Z token=TEST_ONLY_TOKEN error\n'
        with patch.object(d,'journal_library',return_value=j):
            rows=h.docker_view('container_logs',run,'/usr/bin/docker')
            self.assertEqual(rows[0]['at_kst'],'2026-11-08T10:00:00.123456+09:00')
            self.assertNotIn('TEST_ONLY_TOKEN',rows[0]['message']);self.assertEqual(rows[0]['message_state'],'redacted')
            def failed(argv,*args,**kwargs):return (0,catalog) if 'ps' in argv else (1,b'private diagnostic')
            rows=h.docker_view('container_logs',failed,'/usr/bin/docker');self.assertEqual(rows[0]['message_state'],'unavailable')
            self.assertNotIn('private diagnostic',str(rows))

    def test_stderr_capture_cannot_be_used_for_arbitrary_commands(self):
        for argv in ([],['/bin/sh','-c','id'],['/usr/bin/docker','exec','app','id'],
                     ['/usr/bin/docker','logs','--since','15m','--tail','20','--timestamps','--','app']):
            with self.subTest(argv=argv),self.assertRaises(ValueError): d.bounded_command(argv,100,1,docker_logs=True)

    def test_running_failed_and_active_exited_are_distinct(self):
        for state, unit in [('running', 'a.service'), ('failed', 'b.service')]:
            r = h.answer(dict(host='a', view='services', state=state), 'a', NOW, snap())
            self.assertEqual([row['unit'] for row in r['rows']], [unit]); self.assertEqual(r['total'], 1)
        r = h.answer(dict(host='a', view='containers', state='running'), 'a', NOW, snap())
        self.assertEqual(r['rows'][0]['name'], 'app')

    def test_container_catalog_failure_cannot_erase_details_or_prove_absence(self):
        for stale in (False,True):
            s=snap()
            if stale:s['views']['containers']['observed_at']=NOW-181
            else:s['views']['containers'].update(status='unavailable',rows=[],reason='inventory_collection_unavailable')
            args=dict(host='a',view='container_details',container='app')
            r=h.answer(args,'a',NOW,s)
            self.assertEqual(r['status'],'unavailable');self.assertIsNone(r['object_present']);self.assertIsNone(r['total'])
            s['views']['container_details']['rows']=[dict(name='app',field='status',value='running')]
            r=h.answer(args,'a',NOW,s)
            self.assertEqual(r['status'],'observed');self.assertTrue(r['object_present']);self.assertEqual(r['total'],1)

    def test_limits_and_next_page_count_are_exact(self):
        for offset, total, more in [(0, 2, True), (2, 1, False), (100, 0, False)]:
            r = h.answer(dict(host='a', view='services', limit=2, offset=offset), 'a', NOW, snap())
            self.assertEqual(len(r['rows']), total); self.assertEqual(r['has_more'], more); self.assertEqual(r['total'], 3)
            self.assertEqual(r['next_offset'], offset + 2 if more else None)

    def test_stale_future_failed_never_means_empty_success(self):
        for at in (NOW - 181, NOW + 1):
            s = snap(); s['views']['services']['observed_at'] = at
            r = h.answer(dict(host='a', view='services'), 'a', NOW, s)
            self.assertEqual(r['status'], 'unavailable'); self.assertIsNone(r['total']); self.assertEqual(r['rows'], [])
        s = snap(); s['views']['services'].update(status='unavailable', reason='inventory_collection_unavailable', rows=[])
        self.assertIsNone(h.answer(dict(host='a', view='services'), 'a', NOW, s)['total'])

    def test_bad_scope_write_paths_and_boolean_limits_refused(self):
        for change in ({'host': 'thor'}, {'host': '../a'}, {'view': 'shell'}, {'command': 'id'},
                       {'limit': True}, {'limit': 101}, {'limit': 0}, {'offset': -1}, {'offset': 4097},
                       {'state': 'active'}, {'view': 'ports', 'state': 'running'}, {'view': 'containers', 'state': 'failed'}):
            with self.subTest(change=change), self.assertRaises(ValueError): h.request({'host':'a', 'view':'services', **change})

    def test_remote_host_and_extra_columns_refused(self):
        with self.assertRaises(ValueError): h.answer(dict(host='b', view='services'), 'a', NOW, snap())
        for key, value in [('command', 'secret'), ('unit', 'x\nforged')]:
            s = snap(); s['views']['services']['rows'][0][key] = value
            with self.assertRaises(ValueError): h.answer(dict(host='a', view='services'), 'a', NOW, s)

    def test_fixed_commands_return_no_environment_arguments_or_container_command(self):
        seen = []
        def run(argv, bound, timeout):
            seen.append(argv); self.assertLessEqual(timeout, 5)
            if 'list-units' in argv:
                return 0, json.dumps([dict(unit='x.service', load='loaded', active='active', sub='running', description='ignored')]).encode()
            if 'ps' in argv:
                return 0, json.dumps(dict(ID='a', Names='app', Image='img', State='running', Status='Up', Command='SECRET')).encode()
            if argv[0].endswith('/ss'): return 0, b'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n'
            return 0, b'1 daemon 2.0 1.0\n'
        for view in ('services', 'containers', 'ports', 'processes'):
            result = h.collect_view(view, run, '/usr/bin/docker')
            self.assertEqual(len(result), 1); self.assertNotIn('SECRET', str(result)); self.assertEqual(set(result[0]), set(h.COLUMNS[view]))
        self.assertFalse(any('sh' in argv or 'args' in str(argv) or 'inspect' in argv for argv in seen))

    def test_bad_output_is_not_silently_truncated(self):
        for raw in (b'not json', json.dumps([dict(unit='x', load='x', active='x', sub='x')] * 4097).encode()):
            with self.assertRaises(ValueError): h.collect_view('services', lambda *args: (0, raw), '/usr/bin/docker')


if __name__ == '__main__': unittest.main()
