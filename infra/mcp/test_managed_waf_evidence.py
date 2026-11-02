"""Synthetic provenance, policy, refusal and integration checks; no network."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import incident_containment as c
import managed_waf_evidence as w
import managed_suricata_evidence as s
from test_incident_containment import NOW, PUBLIC, Engine, FakeBackend
import test_managed_suricata_evidence as fixtures
BOOT = fixtures.BOOT

BINDING = "a" * 64


def event():
    seen = NOW - 20
    stamp = datetime.fromtimestamp(seen, timezone.utc)
    return {"transaction": {"unique_id": f"v2:{BINDING}:" + "b"*32 + f":{seen}.123:" + stamp.isoformat(),
        "time_stamp": stamp.strftime("%a %b %d %H:%M:%S %Y"), "is_interrupted": True,
        "client_ip": PUBLIC, "client_port": 56789, "host_ip": "172.18.0.2", "host_port": 8080,
        "request": {"uri": "/private?secret=unused", "headers": {"Cookie": "not-returned"}},
        "response": {"http_code": 403}, "producer": {"secrules_engine": "Enabled"},
        "messages": [{"details": {"ruleId": "941100", "tags": ["attack-xss"], "severity": "2"}}]}}


class WafPolicy(unittest.TestCase):
    def parse(self, value=None):
        return w.parse_event(json.dumps(value or event()), BINDING)

    def test_minimal_kst_facts_and_transactions_not_flows(self):
        row = self.parse()
        self.assertTrue(row["timestamp"].endswith("+09:00"))
        self.assertNotIn("secret", json.dumps(row)); self.assertNotIn("Cookie", json.dumps(row))
        value = w.validated_evidence([row, row], PUBLIC, NOW, "172.18.0.2", 8080)
        self.assertEqual(value["http_transactions"], 1)
        self.assertEqual(value["independent_flows"], 0)
        tls = dict(row, dest_port=8443)
        self.assertEqual(w.validated_evidence([tls], PUBLIC, NOW, "172.18.0.2", [8080,8443])["http_transactions"], 1)

    def test_duplicate_headers_allowed_structural_duplicates_refused(self):
        raw = json.dumps(event()).replace('"http_code": 403', '"headers":{"Server":"a","Server":"b"},"http_code":403')
        self.assertEqual(w.parse_event(raw, BINDING)["rule_ids"], [941100])
        for before, after in [('"http_code":403', '"http_code":200,"http_code":403'),
                              ('"is_interrupted": true', '"is_interrupted":false,"is_interrupted":true')]:
            with self.subTest(before=before), self.assertRaises(w.EvidenceUnavailable):
                w.parse_event(raw.replace(before, after), BINDING)

    def test_denial_mode_binding_clock_source_ports_required(self):
        paths = [(('is_interrupted',), False), (('response','http_code'), 200),
                 (('response','http_code'), '403'), (('producer','secrules_engine'), 'DetectionOnly'),
                 (('client_port',), 0), (('host_port',), True), (('client_ip',), '192.168.016.233'),
                 (('unique_id',), 'unverified'), (('time_stamp',), 'invalid')]
        for path, value in paths:
            e = event(); target=e['transaction']
            for key in path[:-1]: target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path), self.assertRaises((ValueError, KeyError, TypeError)):
                self.parse(e)
        raw=json.dumps(event())
        with self.assertRaises(w.EvidenceUnavailable): w.parse_event(raw,'c'*64)
        e=event(); e['transaction']['unique_id']=e['transaction']['unique_id'].replace('+00:00','')
        with self.assertRaises(w.EvidenceUnavailable): self.parse(e)

    def test_only_concrete_attack_tags_no_anomaly_protocol_scanner_or_boolean_severity(self):
        for rid,tags,severity in [('949110',['anomaly-evaluation'],'2'),
                                  ('920350',['attack-protocol'],'4'), ('913100',['attack-reputation-scanner'],'2'),
                                  ('941100',['attack-xss'],True),('941100',['attack-xss'],'5')]:
            e=event();e['transaction']['messages'][0]['details']={'ruleId':rid,'tags':tags,'severity':severity}
            with self.subTest(rid=rid,severity=severity), self.assertRaises(w.EvidenceUnavailable):self.parse(e)

    def test_stale_wrong_target_and_transaction_conflict_refused(self):
        row=self.parse()
        for ip,now,dest,port in [(PUBLIC,NOW+301,'172.18.0.2',8080),('192.168.16.80',NOW,'172.18.0.2',8080),
                                 (PUBLIC,NOW,'172.18.0.3',8080),(PUBLIC,NOW,'172.18.0.2',8443)]:
            with self.assertRaises(w.EvidenceUnavailable):w.validated_evidence([row],ip,now,dest,port)
        with self.assertRaises(w.EvidenceUnavailable):
            w.validated_evidence([row,dict(row,rule_ids=[942100])],PUBLIC,NOW,'172.18.0.2',8080)

    def test_independent_waf_fallback_and_native_reader_stays_suricata_only(self):
        result={'sensor':'a:modsecurity'}
        with mock.patch.object(c,'read_suricata_evidence',side_effect=c.ContainmentError('no flow')), \
             mock.patch.object(c,'_reader_namespace',side_effect=[{'read_evidence':lambda ip,now,common:result},{}]):
            self.assertEqual(c.read_evidence(PUBLIC,NOW),result)
        with mock.patch.object(c,'read_suricata_evidence',return_value={'sensor':'a:suricata'}), \
             mock.patch.object(c,'_reader_namespace') as load:
            self.assertEqual(c.read_evidence(PUBLIC,NOW)['sensor'],'a:suricata');load.assert_not_called()
        with self.assertRaises(c.ContainmentError):c.read_evidence('211.170.162.85',NOW)
        for ip in ('172.18.0.2','172.18.0.3','172.19.0.2'):
            with self.assertRaises(c.ContainmentError): c.read_evidence(ip,NOW)

    def test_existing_workflow_card_ttl_and_release_with_waf_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            engine=Engine(directory);backend=FakeBackend(engine)
            proof=w.validated_evidence([self.parse()],PUBLIC,NOW,'172.18.0.2',8080)
            service=c.ContainmentService(engine,backend,lambda ip,now:proof)
            result=service.propose(PUBLIC,'WAF denied an inbound attack')
            self.assertEqual(result['independent_flows'],0)
            self.assertEqual(result['http_transactions'],1)
            self.assertEqual(result['evidence_sensor'],'a:modsecurity')
            self.assertEqual(result['owned_deadline'],NOW+600)
            self.assertEqual(len(engine.broker.cards),1)
            self.assertEqual(service.propose(PUBLIC,'duplicate')['owned_deadline'],NOW+600)
            self.assertEqual(backend.creates,1)
            engine.now=NOW+601;service.worker_once()
            self.assertFalse(backend.entries)

    def test_live_writer_pins_process_config_pointer_and_proxy_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);proc=root/'proc';base=root/'raw';managed=base/'capstone-managed'
            managed.mkdir(parents=True);gen=managed/'generation-0000000001.jsonl';gen.write_bytes(b'{}\n')
            pointer=('SecAuditLog /var/log/modsecurity/capstone-managed/'+gen.name+'\n').encode()
            (managed/'audit-path.conf').write_bytes(pointer);(managed/'audit-path.conf').chmod(0o444)
            config=b'configuration';producer=('v2:'+BINDING+':$request_id:$msec:$time_iso8601').encode()
            policy={'container_id':'c'*64,'proxy_container_id':'d'*64,'deployment_binding':BINDING,
                    'proxy_config_sha256':hashlib.sha256(config).hexdigest(),
                    'config_sha256':{name:hashlib.sha256(producer if 'evidence.conf' in name else config).hexdigest() for name in w.CONFIGS}}
            state={'current':{'basename':gen.name,'writer_config_sha256':hashlib.sha256(pointer).hexdigest(),
                    'device':gen.stat().st_dev,'inode':gen.stat().st_ino},'source_pins':{
                    'container_id':policy['container_id'],'engine_config_sha256':hashlib.sha256(config).hexdigest(),
                    'producer_format_sha256':hashlib.sha256(producer).hexdigest()}}
            for pid,cid in [('11',policy['container_id']),('12',policy['proxy_container_id'])]:
                p=proc/pid;(p/'fd').mkdir(parents=True);(p/'fdinfo').mkdir();(p/'net').mkdir()
                (p/'comm').write_text('nginx\n');(p/'cgroup').write_text('0::/system.slice/docker-'+cid+'.scope\n')
                (p/'exe').symlink_to('/usr/sbin/nginx');(p/'stat').write_text(pid+' (nginx) S '+'0 '*18+'500')
                (p/'status').write_text('Uid: 101 101 101 101\nGid: 101 101 101 101\n')
                for name in w.CONFIGS:
                    target=p/('root'+name);target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes(producer if 'evidence.conf' in name and pid=='11' else config)
                (p/'net/fib_trie').write_text('|-- 172.18.0.3\n   /32 host LOCAL\n')
                (p/'fd/5').symlink_to(gen);(p/'fdinfo/5').write_text('flags: 0102001\n')
            def read(path,limit,mode=None,owner=0):
                return s.read_fixed(path,limit,mode,os.geteuid() if owner==0 else owner)
            common={'read_fixed':read}
            with mock.patch.object(w,'BASE',base):
                result=w.writer_snapshot(state,common,policy,proc)
                self.assertEqual(result['waf'][0]['pid'],11);self.assertEqual(result['proxy'][0]['pid'],12)
                for target,bad in [('11/root/etc/nginx/nginx.conf',b'changed'),('11/fdinfo/5',b'flags: 0100000\n'),
                                   ('12/net/fib_trie',b'|-- 172.18.0.1\n /32 host LOCAL\n')]:
                    p=proc/target;old=p.read_bytes();p.write_bytes(bad)
                    with self.subTest(target=target),self.assertRaises((ValueError,OSError)):
                        w.writer_snapshot(state,common,policy,proc)
                    p.write_bytes(old)


class WafManaged(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ManagedEvidence();self.fixture.setUp();f=self.fixture
        (f.managed/'active.jsonl').unlink();(f.base/'eve.json').rename(f.base/'audit.log')
        f.obj['engine']='modsecurity';f.obj['current']['writer_config_sha256']='f'*64;f.save()
        f.gen.write_text(json.dumps(event())+'\n')

    def tearDown(self): self.fixture.tearDown()

    def scan(self):
        f=self.fixture
        return s._events(f.state,f.base,f.pins,BOOT,root_uid=os.geteuid(),root_gid=os.getegid(),
            sensor_uid=os.geteuid(),sensor_gid=os.getegid(),trusted_state_ancestors=False,
            engine='modsecurity',writer_probe=self.writer,parse_line=lambda raw:w.parse_event(raw,BINDING))

    def test_two_links_current_generation_requires_writer_twice_even_same_boot(self):
        self.writer=mock.Mock(return_value={'pid':1})
        rows,proof=self.scan();self.assertEqual(len(rows),1);self.assertEqual(proof['link_count'],2)
        self.assertEqual(self.writer.call_count,2)
        self.writer=mock.Mock(side_effect=[{'pid':1},{'pid':2}])
        with self.assertRaises(s.EvidenceUnavailable):self.scan()

    def test_extra_link_partial_line_and_changed_pins_not_admitted(self):
        self.writer=mock.Mock(return_value={'pid':1});f=self.fixture
        f.gen.write_text(json.dumps(event()))
        self.assertEqual(self.scan()[0],[])
        f.gen.write_text(json.dumps(event())+'\n')
        os.link(f.gen,f.root/'extra')
        with self.assertRaises(s.EvidenceUnavailable):self.scan()
        (f.root/'extra').unlink();f.pins['vector_env_sha256'].write_bytes(b'changed')
        with self.assertRaises(s.EvidenceUnavailable):self.scan()


if __name__ == '__main__':unittest.main()
