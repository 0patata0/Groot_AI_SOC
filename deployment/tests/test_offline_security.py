"""Read-only/config fixtures; never connects to a server or real Docker daemon."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deployment'))
import offline_security as s


class SecurityFixtures(unittest.TestCase):
    def test_native_audit_pointer_accepts_only_exact_writer_parent(self):
        pointer=Path('/opt/capstone/security/logs/modsecurity/capstone-managed/audit-path.conf')
        writer=pointer.parent.parent
        def info(path):
            if path==pointer:
                return SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_gid=0,st_nlink=1,st_size=70)
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=101 if path==writer else 0,
                                   st_gid=101 if path==writer else 0)
        with patch.object(Path,'lstat',info):
            self.assertEqual(s.trusted(pointer),pointer)
            with self.assertRaises(s.Refused):s.trusted(pointer,private=True)
            with self.assertRaises(s.Refused):s.trusted(pointer.with_name('arbitrary.conf'))
        def changed(path):
            result=info(path)
            if path==writer:result.st_uid=102
            return result
        with patch.object(Path,'lstat',changed),self.assertRaises(s.Refused):s.trusted(pointer)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.role = Path(self.tmp.name).resolve()
        self.env = {'LAB_PUBLIC_ORIGIN': 'https://lab.example.test:9443', 'LAB_HTTPS_PORT': '9443',
                    'LAB_ALLOWED_CIDRS': '10.20.0.0/24,192.168.40.0/24', 'LAB_PROXY_SUBNET': '172.30.247.0/29',
                    'SERVICE_HOST': '10.20.0.30', 'SECURITY_HOST': '10.20.0.10', 'LAB_GATEWAY_PORT': '18091',
                    'WAF_PORT': '8080', 'CAPSTONE_SOURCE': str(ROOT), 'ROLE_DIR': str(self.role),
                    'LAB_TLS_CERT': str(self.role/'original.crt'), 'LAB_TLS_KEY': str(self.role/'original.key'),
                    'WAF_ID': 'sha256:' + 'a'*64, 'PROFILE': 'b'*64}
        self.environment = patch.dict(os.environ, self.env); self.environment.start(); self.addCleanup(self.environment.stop)
        self.data = s.settings(self.env)
        base = ROOT / 'infra/groot-c/offline-labs'
        self.sources = {name: (base/name).read_text() for name in s.SOURCES}
        self.command = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']

    def compose(self):
        return {'services': {'waf': {'environment': {'MODSEC_RULE_ENGINE': 'DetectionOnly'},
                                    'volumes': [str(self.role/'config/GROOT_A_WAF.conf') + ':/rules/custom.conf:ro',
                                                str(self.role/'logs/modsecurity') + ':/var/log/modsecurity']},
                             'suricata': {'network_mode': 'host'}}, 'networks': {'waf': {'driver': 'bridge'}}}

    def edge(self):
        return {'Image': self.data['image'], 'State': {'Running': True, 'Restarting': False}, 'RestartCount': 0,
                'Config': {'Labels': {'com.docker.compose.project': 'capstone-security', 'com.docker.compose.service': 'lab-edge',
                                     'io.capstone.portable.profile': self.env['PROFILE']}, 'User': '101:101', 'Entrypoint': ['nginx'],
                           'Cmd': ['-c', '/etc/capstone/nginx.conf', '-g', 'daemon off;'], 'WorkingDir': '/tmp',
                           'Healthcheck': {'Test': ['NONE']}, 'Env': ['PATH=/usr/bin']},
                'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'CapDrop': ['ALL'], 'CapAdd': [],
                               'Memory': 134217728, 'NanoCpus': 500000000, 'PidsLimit': 64, 'Tmpfs': s.TMPFS,
                               'SecurityOpt': ['no-new-privileges:true'], 'Devices': [], 'PidMode': '', 'IpcMode': 'private',
                               'RestartPolicy': {'Name': 'unless-stopped'}, 'NetworkMode': s.NETWORK,
                               'PortBindings': {'8443/tcp': [{'HostIp': '10.20.0.10', 'HostPort': '9443'}]},
                               'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}}},
                'Mounts': [{'Type': 'bind', 'Source': str(self.role/'tls'), 'Destination': '/etc/capstone-tls', 'RW': False},
                           {'Type': 'bind', 'Source': str(self.role/'config/lab-edge.conf'), 'Destination': '/etc/capstone/nginx.conf', 'RW': False}]}

    def test_invalid_network_origin_and_port_inputs_fail_closed(self):
        for key, value in [('LAB_PUBLIC_ORIGIN', 'https://lab.example.test:9443/'), ('LAB_PUBLIC_ORIGIN', 'http://lab.example.test:9443'),
                           ('LAB_ALLOWED_CIDRS', '0.0.0.0/0'), ('LAB_ALLOWED_CIDRS', '10.20.0.1/24'),
                           ('LAB_ALLOWED_CIDRS', '172.30.247.0/29'), ('LAB_PROXY_SUBNET', '172.30.247.0/24'),
                           ('LAB_HTTPS_PORT', '443'), ('SERVICE_HOST', '172.30.247.2')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                s.settings({**self.env, key: value})

    def test_rendered_paths_keep_key_exchange_outside_waf_and_unknown_routes_closed(self):
        output = s.render(self.data, self.sources)
        edge, waf, policy = [output[key].decode() for key in ('config/lab-edge.conf','config/lab-waf.conf','config/lab-policy.conf')]
        self.assertIn('proxy_pass http://10.20.0.30:18091/_offline-labs/api/gateway-session;', edge)
        self.assertIn('location = /log4shell/api/gateway-session { return 404; }', edge)
        self.assertIn('proxy_pass_request_headers off;', edge)
        self.assertIn('if ($http_host != "lab.example.test:9443") { return 421; }', edge)
        self.assertEqual(edge.count('auth_request /_capstone_lab_session;'), 3)
        self.assertEqual(edge.count('proxy_pass http://172.30.247.2:8080;'), 3)
        self.assertEqual(edge.count('proxy_set_header Authorization "";'), 3)
        self.assertEqual(edge.count('proxy_set_header Cookie $capstone_lab_java_cookie;'), 3)
        self.assertEqual(edge.count('proxy_set_header X-Capstone-Lab-Mode $capstone_lab_mode;'), 3)
        self.assertIn('allow 10.20.0.0/24;', edge)
        self.assertNotIn('allow 10.200.10.0/24;', edge)
        self.assertIn('https://lab.example.test:9443/log4shell/static/theme.js', edge)
        self.assertIn('172.30.247.3 1;', waf)
        self.assertEqual(waf.count('set_real_ip_from 172.30.247.3;'), 3)
        self.assertEqual(waf.count('if ($capstone_lab_peer_allowed = 0) { return 403; }'), 3)
        self.assertNotIn('capstone_waf_evidence', waf)
        for value in (edge, waf):
            self.assertNotIn('LAB-DVWA', value)
            self.assertIn('location ^~ /log4shell/labs/ { return 404; }', value)
        active = '\n'.join(line for line in policy.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('REQUEST_URI', active)
        self.assertEqual(active.count('@streq lab.example.test:9443'), 3)
        self.assertIn('ctl:ruleEngine=On', active)
        self.assertIn('ctl:ruleEngine=DetectionOnly', active)
        self.assertIn('mode-check-v1', active)

    def test_previous_public_hostname_is_allowed_when_explicit(self):
        data = s.settings({**self.env, 'LAB_PUBLIC_ORIGIN': 'https://log4shell.grootlab.duckdns.org', 'LAB_HTTPS_PORT': '443'})
        self.assertIn(b'server_name log4shell.grootlab.duckdns.org;', s.render(data, self.sources)['config/lab-edge.conf'])

    def test_explicit_public_web_access_preserves_gateway_and_waf_checks(self):
        data = s.settings({**self.env, 'LAB_ALLOWED_CIDRS': 'all'})
        self.assertEqual(data['allowed'], ['all'])
        output = s.render(data, self.sources)
        edge = output['config/lab-edge.conf'].decode()
        self.assertEqual(edge.count('allow all;'), 1)
        self.assertIn('allow all;\n        deny all;', edge)
        self.assertEqual(edge.count('auth_request /_capstone_lab_session;'), 3)
        self.assertIn('location = /log4shell/api/gateway-session { return 404; }', edge)
        private = s.render(self.data, self.sources)
        self.assertEqual(output['config/lab-waf.conf'], private['config/lab-waf.conf'])
        self.assertEqual(output['config/lab-policy.conf'], private['config/lab-policy.conf'])
        self.assertNotIn('allow all;', private['config/lab-edge.conf'].decode())
        for bad in ('all,192.168.10.0/24', 'ALL', 'all;', 'all\n', '::/0', '0.0.0.0/0'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                s.settings({**self.env, 'LAB_ALLOWED_CIDRS': bad})

    def test_edge_compose_is_pinned_nonroot_private_and_no_implicit_bind_creation(self):
        value = s.enhance_compose(self.compose(), self.data, self.env['PROFILE'])
        edge = value['services']['lab-edge']; waf = value['services']['waf']
        self.assertEqual(edge['image'], self.data['image'])
        self.assertEqual(edge['pull_policy'], 'never')
        self.assertEqual(edge['ports'], ['10.20.0.10:9443:8443'])
        self.assertEqual(edge['user'], '101:101'); self.assertTrue(edge['read_only'])
        self.assertEqual(edge['cap_drop'], ['ALL'])
        self.assertEqual(edge['entrypoint'], ['nginx'])
        self.assertEqual(edge['networks'], {'waf': {'ipv4_address': '172.30.247.3'}})
        self.assertEqual(waf['networks'], {'waf': {'ipv4_address': '172.30.247.2'}})
        self.assertEqual(value['services']['suricata'], {'network_mode': 'host'})
        self.assertEqual(waf['environment']['MODSEC_RULE_ENGINE'], 'DetectionOnly')
        self.assertTrue(all(v['read_only'] and v['bind'] == {'create_host_path': False} for v in edge['volumes']))

    def test_runtime_rejects_privilege_mutation_mount_writes_and_wrong_tls_publish(self):
        image = {'Config': {'Env': ['PATH=/usr/bin']}}
        s.edge_contract(self.edge(), self.data, image)
        for section, key, value in [('Config', 'User', '0:0'), ('Config', 'Env', ['LD_PRELOAD=/bad']),
                                    ('HostConfig','ReadonlyRootfs',False), ('HostConfig','Privileged',True),
                                    ('HostConfig','NetworkMode','host'), ('HostConfig','CapAdd',['SYS_ADMIN']),
                                    ('HostConfig','PortBindings', {'8443/tcp':[{'HostIp':'0.0.0.0','HostPort':'9443'}]}),
                                    ('HostConfig','Tmpfs', {'/tmp':'exec'})]:
            current=self.edge();current[section][key]=value
            with self.subTest(key=key), self.assertRaises(s.Refused):
                s.edge_contract(current,self.data,image)
        current=self.edge(); current['Mounts'][0]['RW']=True
        with self.assertRaises(s.Refused):s.edge_contract(current,self.data,image)

    def network_stub(self, networks=None, interfaces=None, routes=None):
        def call(args, **kwargs):
            tail=args[3:] if args[:3]==self.command else args
            if tail[:2]==['network','ls']: return b'n'*64 if networks else b''
            if tail[:2]==['network','inspect']:return json.dumps(networks).encode()
            if tail==['ip','-j','address','show']:return json.dumps(interfaces or []).encode()
            if tail==['ip','-j','route','show','table','all']:return json.dumps(routes or [{'dst':'default','dev':'eth0'}]).encode()
            if tail[:2]==['container','ls']:return b''
            raise AssertionError(args)
        return call

    def test_subnet_conflicts_are_detected_before_network_creation(self):
        cases = [dict(interfaces=[{'ifname':'vpn0','addr_info':[{'family':'inet','local':'172.30.247.4','prefixlen':29}]}]),
                 dict(routes=[{'dst':'172.30.0.0/16','dev':'vpn0'}]),
                 dict(networks=[{'Name':'foreign','IPAM':{'Config':[{'Subnet':'172.30.247.0/29'}]}}])]
        for value in cases:
            with self.subTest(value=value), patch.object(s,'run',side_effect=self.network_stub(**value)), self.assertRaises(s.Refused):
                s.conflicts(self.data,self.command,existing=True)
        own=[{'Name':s.NETWORK,'IPAM':{'Config':[{'Subnet':self.data['subnet']}]},'Labels':{'com.docker.compose.project':'capstone-security'},'Options':{'com.docker.network.bridge.name':'br-own'}}]
        with patch.object(s,'run',side_effect=self.network_stub(networks=own,routes=[{'dst':self.data['subnet'],'dev':'br-own'}])):
            s.conflicts(self.data,self.command,existing=True)

    def test_certificate_requires_san_matching_key_and_never_returns_private_material(self):
        cert=self.role/'original.crt';key=self.role/'original.key'
        cert.write_bytes(b'public certificate fixture');key.write_bytes(b'private fixture not printed')
        def fake(args, **kwargs):
            if '-ext' in args:return b'X509v3 Subject Alternative Name: DNS:lab.example.test'
            if '-pubkey' in args or '-pubout' in args:return b'PUBLIC KEY ONLY'
            if '-checkhost' in args:return b'Hostname lab.example.test does match certificate\n'
            return b''
        with patch.object(s,'trusted',side_effect=lambda path,**kw:Path(path)),patch.object(s,'run',side_effect=fake):
            result=s.certificate(self.data)
            self.assertNotIn('private fixture',json.dumps(result))
            self.assertEqual(set(result),{'certificate_sha256','public_key_sha256'})
        def wrong(args,**kwargs):return b'WRONG KEY' if args[1]=='pkey' else fake(args,**kwargs)
        with patch.object(s,'trusted',side_effect=lambda path,**kw:Path(path)),patch.object(s,'run',side_effect=wrong),self.assertRaisesRegex(s.Refused,'key_mismatch'):
            s.certificate(self.data)
        def mismatch(args,**kwargs):
            return b'Hostname lab.example.test does NOT match certificate' if '-checkhost' in args else fake(args,**kwargs)
        with patch.object(s,'trusted',side_effect=lambda path,**kw:Path(path)),patch.object(s,'run',side_effect=mismatch),self.assertRaisesRegex(s.Refused,'hostname_mismatch'):
            s.certificate(self.data)

    def test_docker_binary_uses_binary_size_budget_and_fixed_local_socket(self):
        with patch.object(s.shutil, 'which', return_value='/usr/local/bin/docker'), patch.object(s, 'trusted') as trust:
            self.assertEqual(s.docker(), ['/usr/local/bin/docker','--host','unix:///var/run/docker.sock'])
            self.assertEqual(trust.call_args.kwargs['limit'], 128*1024*1024)

    def test_only_root_private_upload_stage_can_cross_sticky_var_tmp(self):
        source='/var/tmp/capstone-bootstrap-'+'a'*24+'/source'
        target=Path(source)/'deployment/offline_security.py'
        def metadata(path):
            if path==target:
                return SimpleNamespace(st_mode=stat.S_IFREG|0o644, st_uid=0, st_gid=0, st_nlink=1, st_size=4096)
            mode=0o1777 if str(path)=='/var/tmp' else (0o700 if str(path)==str(Path(source).parent) else 0o755)
            return SimpleNamespace(st_mode=stat.S_IFDIR|mode, st_uid=0, st_gid=0)
        with patch.dict(os.environ, {'CAPSTONE_SOURCE':source}),patch.object(Path,'lstat',metadata):
            self.assertEqual(s.trusted(target),target)
        with patch.dict(os.environ, {'CAPSTONE_SOURCE':'/opt/another-source'}),patch.object(Path,'lstat',metadata),self.assertRaises(s.Refused):
            s.trusted(target)

    def test_profile_hash_changes_with_security_source_and_certificate(self):
        tls={'certificate_sha256':'a'*64,'public_key_sha256':'b'*64}
        base=s.identity(self.data,self.sources,tls)
        self.assertNotEqual(base,s.identity(self.data,{**self.sources,s.SOURCES[2]:self.sources[s.SOURCES[2]]+'\n# changed'},tls))
        self.assertNotEqual(base,s.identity(self.data,self.sources,{**tls,'certificate_sha256':'c'*64}))

    def native_case(self, *, failure=False, wrong_owner=False):
        compose=s.enhance_compose(self.compose(),self.data,self.env['PROFILE'])
        (self.role/'compose.json').write_text(json.dumps(compose))
        calls=[];counter=0
        def fake(args,**kwargs):
            nonlocal counter
            calls.append(args)
            tail=args[3:]
            if tail[0]=='create':counter+=1;return (str(counter)*64).encode()
            if tail[0]=='inspect':return json.dumps([{'Id':tail[-1],'Image':self.data['image'],'State':{'Running':False,'ExitCode':1 if failure else 0},
                      'Config':{'Labels':{'io.capstone.portable.labcheck':'wrong' if wrong_owner else self.env['PROFILE']}}}]).encode()
            if tail[0]=='rm':return b''
            raise AssertionError(args)
        with patch.object(s,'run',side_effect=fake),patch.object(s.subprocess,'run',return_value=SimpleNamespace(returncode=1 if failure else 0)):
            if failure or wrong_owner:
                with self.assertRaises(s.Refused):s.native(self.data,self.command)
            else:s.native(self.data,self.command)
        return calls

    def test_native_config_checks_are_networkless_and_cleanup_only_owned_ids(self):
        calls=self.native_case()
        creates=[a for a in calls if a[3]=='create'];removes=[a for a in calls if a[3]=='rm']
        self.assertEqual(len(creates),2);self.assertEqual(len(removes),2)
        for args in creates:
            self.assertEqual(args[args.index('--network')+1],'none')
            self.assertEqual(args[args.index('--pull')+1],'never')
            self.assertNotIn('--publish',args)
        self.assertIn('--read-only',creates[0])
        self.assertEqual([a[-1] for a in removes],['1'*64,'2'*64])

    def test_failed_native_check_removes_owned_container_then_stops(self):
        calls=self.native_case(failure=True)
        self.assertEqual(len([a for a in calls if a[3]=='create']),1)
        self.assertEqual([a[-1] for a in calls if a[3]=='rm'],['1'*64])

    def test_changed_native_identity_is_not_removed(self):
        calls=self.native_case(wrong_owner=True)
        self.assertFalse(any(a[3]=='rm' for a in calls))

    def test_security_role_calls_private_validation_before_public_mutation(self):
        shell=(ROOT/'deployment/roles/security.sh').read_text()
        apply=shell[shell.index('apply_role() {'):]
        self.assertLess(apply.index('lab_security render'),apply.index('compose config --quiet'))
        self.assertLess(apply.index('lab_security native'),apply.index('nft -f "$ROLE_DIR/config/firewall.nft"'))
        self.assertLess(apply.index('lab_security native'),apply.index('compose up -d'))
        self.assertIn('.schema_version==2',shell)
        self.assertIn("'LAB_PROFILE'",shell)


if __name__=='__main__':unittest.main()
