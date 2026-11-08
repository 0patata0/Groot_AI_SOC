"""Short current queries retain full requested scope and actual receipts."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import harness as h

spec = importlib.util.spec_from_file_location('inventory_mcp', Path(__file__).parents[1]/'mcp/system-diagnostics-mcp.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
NAME = h.HOST_INVENTORY_TOOL


def receipt(args):
    columns = {'services':dict(unit='x.service', load='loaded', active='active', sub='running'),
               'containers':dict(id='abc', name='app', image='fixture', state='running', status='Up'),
               'ports':dict(protocol='tcp', state='LISTEN', local='*:80', peer='*:*'),
               'resources':dict(metric='load_1m', value='1.2', unit='runnable_tasks'),
               'processes':dict(pid='1', name='init', cpu_percent='0.0', memory_percent='0.1')}
    rows = [{**args, 'host': host, 'status':'observed', 'reason':None, 'total':1, 'rows':[columns[args['view']]],
             'age_seconds':1, 'observed_at_kst':'2026-11-08T14:00:00+09:00', 'has_more':False, 'next_offset':None}
            for host in ('abc' if args['host']=='all' else [args['host']])]
    data = dict(schema=1, kind='host_inventory', request=args, hosts=rows)
    return seal(dict(server='system-diagnostics', name='get_host_inventory', arguments=args, is_error=False, is_write=False),data)


def seal(call, data):
    raw=json.dumps(data);return {**call,'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}


class HostLookup(unittest.TestCase):
    def test_capacity_units_use_exact_source_and_at_most_two_decimals(self):
        for value,unit,want in [('107374182400','bytes','107.37 GB (107,374,182,400 bytes)'),
                                ('1000000000000','B','1 TB (1,000,000,000,000 B)'),
                                ('16777216','KiB','17.18 GB (16,777,216 KiB)'),
                                ('0','bytes','0 B (0 bytes)'),('1000','B','1 kB (1,000 B)')]:
            with self.subTest(value=value,unit=unit):self.assertEqual(h.capacity_text(value,unit),want)
        for value,unit in [('infinity','bytes'),('[not set]','bytes'),('-1','bytes'),('1','%'),('NaN','B')]:
            self.assertIsNone(h.capacity_text(value,unit))

    def test_memory_swap_and_docker_use_same_capacity_rule_not_rate_or_ids(self):
        self.assertEqual([r['view'] for r in h.host_inventory_request('메모리랑 스왑 보여줘')],['resources'])
        self.assertEqual([r['view'] for r in h.host_inventory_request('B 서버 디스크 상태 보여줘')],['storage'])
        self.assertEqual({r['view'] for r in h.host_inventory_request('메모리랑 디스크 보여줘')},{'resources','storage'})
        for metric in ('MemTotal','MemAvailable','SwapTotal','SwapFree'):
            row=dict(metric=metric,value='16777216',unit='KiB')
            self.assertEqual(h.inventory_capacity_cell('resources',row,'value'),'17.18 GB (16,777,216 KiB)')
        stats=dict(name='hermes',field='MemUsage',value='270.5MiB / 15.62GiB')
        self.assertEqual(h.inventory_capacity_cell('container_stats',stats,'value'),
                         '약 283.64 MB (270.5 MiB) / 약 16.77 GB (15.62 GiB)')
        for field,value in [('CPUPerc','25.00%'),('PIDs','30'),('MemUsage','N/A / 2GiB')]:
            self.assertIsNone(h.inventory_capacity_cell('container_stats',dict(name='x',field=field,value=value),'value'))
        self.assertIsNone(h.inventory_capacity_cell('service_details',dict(unit='ssh.service',field='MemoryMax',value='infinity'),'value'))

    def test_capacity_render_preserves_original_receipt_and_host_partition(self):
        q='서버 메모리 얼마나 남았어';args=h.host_inventory_request(q)[0];call=receipt(args);data=json.loads(call['result'])
        for row in data['hosts']:row['rows']=[dict(metric='SwapFree',value='16777216',unit='KiB')]
        call=seal(call,data);original=copy.deepcopy(call);text=h.lookup_report(q,[call])
        self.assertEqual(text.count('17.18 GB (16,777,216 KiB)'),3)
        self.assertEqual(call,original);self.assertFalse(h.missing_reads(q,[call]))
        self.assertIn('**A 서버**',text);self.assertIn('**B 서버**',text);self.assertIn('**C 서버**',text)

    def test_named_docker_and_os_details_are_not_replaced_by_curated_status(self):
        for q,view,subject in [('헤르메스 컨테이너 상세 보여줘','container_details',('container','hermes')),
                              ('B 서버 hermes 컨테이너 로그 보여줘','container_logs',('container','hermes')),
                              ('waf 컨테이너 상태 보여줘','container_details',('container','waf')),
                              ('C 서버 apache2.service 상세 보여줘','service_details',('unit','apache2.service'))]:
            with self.subTest(q=q):
                request=h.host_inventory_request(q)[0];self.assertEqual(request['view'],view)
                self.assertEqual(request[subject[0]],subject[1]);self.assertIsNone(h.diagnostic_request(q))
                self.assertTrue(h.refine_read_schemas(q,{NAME:m.INVENTORY_TOOL['inputSchema']},[]))
        for q in ('hermes 컨테이너 환경변수 보여줘','hermes 도커 비밀번호 보여줘',
                  'hermes 컨테이너 어제 로그 보여줘','hermes 컨테이너 exec 해줘','ssh.service 삭제해줘'):
            with self.subTest(q=q):self.assertIsNone(h.host_inventory_request(q))

    def test_named_container_followups_keep_name_and_host(self):
        q='B 서버 hermes 컨테이너 상세 보여줘'
        request=h.host_inventory_request(h.resolve_short_read('로그도 보여줘',[q]))[0]
        self.assertEqual((request['container'],request['host'],request['view']),('hermes','b','container_logs'))
        request=h.host_inventory_request(h.resolve_short_read('다음 페이지',[q]))[0]
        self.assertEqual((request['container'],request['offset']),('hermes',100))

    def test_plain_service_query_covers_systemd_and_containers(self):
        for q in ('지금 실행중인 서비스 보여줘','돌아가는 서비스 목록','가동 중인 서비스 알려줘'):
            with self.subTest(q=q):
                req=h.host_inventory_request(q); self.assertEqual({r['view'] for r in req},{'services','containers'})
                self.assertTrue(all(r['state']=='running' and r['host']=='all' for r in req))
                self.assertTrue(h.structured_read(q));self.assertEqual(h.tool_scope(q),{NAME})
                self.assertEqual(h.workflow_names(q),('soc-query',));self.assertTrue(h.EVIDENCE.allowed(NAME,'verify'))

    def test_alternative_query_families_and_host(self):
        for q,view in [('B 서버 컨테이너 목록','containers'),('A 서버 열린 포트 보여줘','ports'),
                       ('C 서버 CPU 메모리 사용량','resources'),('프로세스 목록','processes'),
                       ('실패한 서비스 보여줘','services')]:
            with self.subTest(q=q): self.assertEqual(h.host_inventory_request(q)[0]['view'],view)
        self.assertEqual(h.host_inventory_request('B 서버 컨테이너 목록')[0]['host'],'b')

    def test_unknown_filters_writes_causal_ranges_or_unbounded_are_not_erased(self):
        for q in ('서비스 재시작해줘','서비스 원인 분석','어제 서비스 목록','서비스 192.0.2.1 조회',
                  'B C 서버 서비스 보여줘','서비스 0개','서비스 101개','서비스 -1개','전체 서비스 보여줘',
                  'CPU 90% 이상인 것만','서비스 오류 원인과 복구','포트 열어줘','컨테이너 환경변수 보여줘'):
            with self.subTest(q=q): self.assertIsNone(h.host_inventory_request(q))

    def test_schema_uses_registered_bounds_and_stops_blind_retries(self):
        q='지금 실행중인 서비스 보여줘';schema={NAME:m.INVENTORY_TOOL['inputSchema']}
        got=h.refine_read_schemas(q,schema,[])[NAME]
        self.assertEqual(got['properties']['view']['enum'],['services','containers'])
        self.assertEqual(got['properties']['host']['enum'],['all']); self.assertEqual(set(got['required']),{'host','view','state','limit','offset'})
        req=h.host_inventory_request(q);first=receipt(req[0]);second=receipt(req[1])
        self.assertEqual(h.refine_read_schemas(q,schema,[first])[NAME]['properties']['view']['enum'],['containers'])
        self.assertEqual(h.refine_read_schemas(q,schema,[first,dict(second,is_error=True)]),{})
        bad=copy.deepcopy(schema);bad[NAME]['properties']['limit']['maximum']=10
        self.assertEqual(h.refine_read_schemas(q,bad,[]),{})

    def test_complete_table_requires_both_real_views(self):
        q='지금 실행중인 서비스 보여줘';calls=[receipt(r) for r in h.host_inventory_request(q)]
        self.assertEqual(h.missing_reads(q,calls),[]);self.assertTrue(h.missing_reads(q,calls[:1]))
        text=h.lookup_report(q,calls)
        self.assertIn('x.service',text);self.assertIn('app',text);self.assertIn('기능 정상 판정이 아닙니다',text)
        self.assertIn('| 호스트 |',text)
        self.assertTrue(h.missing_reads(q,[dict(calls[0],result_sha256='0'*64),calls[1]]))

    def test_one_host_failure_preserves_other_host_evidence_but_not_completion(self):
        q='컨테이너 목록';call=receipt(h.host_inventory_request(q)[0]);data=json.loads(call['result'])
        data['hosts'][1].update(status='unavailable',reason='inventory_read_unavailable',rows=[],total=None,has_more=None,next_offset=None)
        call=seal(call,data);self.assertTrue(h.missing_reads(q,[call]))
        text=h.lookup_report(q,[call]);self.assertIn('app',text);self.assertIn('inventory_read_unavailable',text)
        self.assertNotIn('조회 범위 내 0건',text)

    def test_detail_tables_separate_hosts_without_losing_rows_or_failures(self):
        q='지금 실행중인 서비스 보여줘'
        calls=[]
        for args in h.host_inventory_request(q):
            call=receipt(args);data=json.loads(call['result'])
            key='unit' if args['view']=='services' else 'name'
            for row in data['hosts']:row['rows'][0][key]=row['host']+'-'+args['view']
            calls.append(seal(call,data))
        text=h.host_inventory_report(q,calls)
        for host in 'abc':
            section=text.split('**'+host.upper()+' 서버**',1)[1].split(' 서버**',1)[0]
            self.assertIn('| '+host+'-services |',section)
            self.assertIn('| '+host+'-containers |',section)
            for other in set('abc')-{host}:
                self.assertNotIn('| '+other+'-services |',section)
                self.assertNotIn('| '+other+'-containers |',section)
        self.assertEqual(text.count('| 서비스 | 적재 | 활성 | 실행 상태 |'),3)
        self.assertNotIn('| 호스트 | 서비스 |',text)
        self.assertNotIn('프로세스 CPU',text)
        call=calls[0];data=json.loads(call['result'])
        data['hosts'][1].update(status='unavailable',reason='collector_failed',rows=[],total=None,has_more=None,next_offset=None)
        calls[0]=seal(call,data);text=h.host_inventory_report(q,calls)
        self.assertIn('collector_failed',text.split('**B 서버**',1)[1].split('**C 서버**',1)[0])
        self.assertIn('| c-services |',text.split('**C 서버**',1)[1])

    def test_followup_page_count_and_failed_filter_retain_scope_not_facts(self):
        q='B 서버 서비스 10개 보여줘'
        resolved=h.resolve_short_read('다음 페이지',[q]);requests=h.host_inventory_request(resolved)
        self.assertTrue(all(r['host']=='b' and r['offset']==10 and r['limit']==10 for r in requests))
        failed=h.host_inventory_request(h.resolve_short_read('오류난 것만 보여줘',[q]))
        self.assertEqual(failed,[dict(host='b',view='services',state='failed',limit=10,offset=0)])
        self.assertEqual(h.resolve_short_read('재시작해줘',[q]),'재시작해줘')


if __name__=='__main__':unittest.main()
