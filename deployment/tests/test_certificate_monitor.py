"""Portable bindings, unchanged probe core, refusal and rule-routing regressions."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'deployment'))
import certificate_monitor as cm

ENV={'SECURITY_HOST':'192.0.2.10','SIEM_HOST':'192.0.2.20','SERVICE_HOST':'192.0.2.30',
     'LAB_PUBLIC_ORIGIN':'https://lab.example.org','LAB_HTTPS_PORT':'443','LAB_PROXY_SUBNET':'172.30.247.0/29'}
TEMPLATES=cm.templates(ROOT,lambda p:p.read_bytes())

class PortableCertificates(unittest.TestCase):
    def test_existing_services_use_distinct_public_inputs_and_fixed_internal_endpoints(self):
        specs=cm.site_specs(ENV);a=specs['security'];b=specs['siem']
        self.assertEqual(a['domain'],'lab.example.org');self.assertEqual(a['connect'],'172.30.247.3:8443')
        self.assertEqual(b['domain'],'capstone-siem.internal');self.assertEqual(b['connect'],'192.0.2.20:8444')
        self.assertNotEqual(a['certificate'],b['certificate'])
        self.assertEqual(a['certificate'],'/opt/capstone/security/tls/lab.crt')
        self.assertEqual(b['certificate'],'/etc/capstone-internal-tls/server.crt')

    def test_local_controller_paths_and_caller_probe_destinations_are_not_inputs(self):
        self.assertEqual(cm.site_specs(ENV),cm.site_specs({**ENV,'CM_CERT':'/tmp/x','CM_DOMAIN':'evil.invalid','CM_CONNECT':'8.8.8.8:443'}))
        with self.assertRaises(cm.Refused):cm.site_specs({**ENV,'CAPSTONE_ROOT':'/tmp/capstone'})

    def test_malicious_or_non_dns_origins_are_refused(self):
        for value in ['http://lab.example.org','https://lab.example.org;id','https://u:p@lab.example.org',
                      'https://lab.example.org/a','https://lab.example.org?a=x','https://lab.example.org#f',
                      'https://lab..example.org','https://*.example.org','https://192.0.2.10',
                      'https://capstone-siem.internal','https://lab.example.org:8443']:
            with self.subTest(value=value),self.assertRaises((cm.Refused,ValueError)):
                cm.site_specs({**ENV,'LAB_PUBLIC_ORIGIN':value})

    def test_proxy_overlap_duplicate_hosts_and_wide_network_are_refused(self):
        for changes in [{'LAB_PROXY_SUBNET':'0.0.0.0/0'},{'LAB_PROXY_SUBNET':'172.30.247.1/29'},
                        {'LAB_PROXY_SUBNET':'172.30.247.0/24'},{'SECURITY_HOST':'172.30.247.1'},
                        {'SIEM_HOST':ENV['SECURITY_HOST']},{'SECURITY_HOST':'127.0.0.1'}]:
            with self.subTest(changes=changes),self.assertRaises((cm.Refused,ValueError)):
                cm.site_specs({**ENV,**changes})

    def test_probe_logic_is_identical_after_reversing_the_declared_site_substitutions(self):
        raw=TEMPLATES['monitor.sh'];original=raw.decode()
        for spec in cm.site_specs(ENV).values():
            result=cm.monitor(raw,spec,'b'*32).decode()
            for new,old in [(spec['domain'],cm.OLD_DOMAIN),(spec['certificate'],'/home/groot_a/capstone/chatproxy/tls/chatduck.crt'),
                            ('b'*32,cm.OLD_MID),(spec['connect'],'172.18.0.3:8443'),('== 0:0:444:1','== 0:0:644:1')]:
                result=result.replace(new,old)
            self.assertEqual(result,original)

    def test_mutated_original_probe_or_noncanonical_host_id_is_refused(self):
        a=cm.site_specs(ENV)['security']
        with self.assertRaises(cm.Refused):cm.monitor(TEMPLATES['monitor.sh']+b'\n',a,'b'*32)
        for mid in ['b'*31,'B'*32,'b'*32+';id']:
            with self.assertRaises(cm.Refused):cm.monitor(TEMPLATES['monitor.sh'],a,mid)

    def test_root_wrapper_and_private_key_exclusion_are_retained(self):
        for spec in cm.site_specs(ENV).values():
            runtime=cm.monitor(TEMPLATES['monitor.sh'],spec,'b'*32).decode()
            self.assertIn('== '+'b'*32,runtime)
            self.assertIn('-verify_return_error -verify_hostname "$CM_DOMAIN"',runtime)
            self.assertIn('-CAfile /etc/ssl/certs/ca-certificates.crt',runtime)
            self.assertIn('== 0:0:444:1',runtime)
            self.assertNotIn(spec['private_key'],runtime)
            self.assertNotIn('curl',runtime);self.assertNotIn('docker',runtime.lower().split('cm_meta()',1)[1])
            unit=cm.service(spec).decode()
            self.assertIn('InaccessiblePaths=-'+spec['private_key'],unit)
            self.assertEqual(re.findall(r'(?m)^IPAddressAllow=(.*)$',unit),['127.0.0.1/32',spec['address']+'/32'])
            self.assertIn('IPAddressDeny=any',unit);self.assertIn('CapabilityBoundingSet=\n',unit)

    def test_generated_shell_has_valid_syntax(self):
        for spec in cm.site_specs(ENV).values():
            result=subprocess.run(['bash','-n'],input=cm.monitor(TEMPLATES['monitor.sh'],spec,'b'*32),capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_severe_expiry_cannot_be_lowered_by_failed_transport_for_either_sensor(self):
        rules=ET.fromstring(b'<root>'+cm.rules(TEMPLATES['capstone_certificate_rules.xml'],cm.site_specs(ENV))+b'</root>')
        for offset in [0,6]:
            for delta,level in [(2,'5'),(3,'7'),(4,'10')]:
                rule=rules.find('.//rule[@id="'+str(100300+offset+delta)+'"]')
                self.assertEqual(rule.get('level'),level)
                self.assertNotIn('probe_status',[n.get('name') for n in rule.findall('field')])
            failure=rules.find('.//rule[@id="'+str(100305+offset)+'"]')
            self.assertEqual(failure.find('field[@name="expiry_status"]').text,'^(ok|within_30_days|unknown)$')

    def test_rules_bind_domain_and_agent_as_pairs_and_keep_disjoint_ids(self):
        specs=cm.site_specs(ENV)
        root=ET.fromstring(b'<root>'+cm.rules(TEMPLATES['capstone_certificate_rules.xml'],specs)+b'</root>')
        self.assertEqual({int(n.get('id')) for n in root.findall('.//rule')},set(range(100300,100312)))
        for index,role in enumerate(['security','siem']):
            base=root.find('.//rule[@id="'+str(100300+index*6)+'"]');spec=specs[role]
            self.assertEqual(base.findtext('program_name'),'^capstone-cert-monitor$')
            self.assertEqual(base.findtext('location'),r'^\('+spec['sensor']+r'\) any->journald$')
            self.assertIn('"domain":"'+re.escape(spec['domain'])+'"',base.findtext('match'))
            self.assertNotIn(cm.OLD_DOMAIN,ET.tostring(base).decode())
            for n in root.findall('.//rule')[index*6+1:index*6+6]:
                self.assertEqual(n.findtext('if_sid'),str(100300+index*6))

    def test_timer_uses_same_explicit_korea_calendar(self):
        self.assertIn(b'OnCalendar=*-*-* 09:00:00 Asia/Seoul',cm.timer())
        self.assertIn(b'Persistent=true',cm.timer())

    def test_partial_installation_is_not_adopted_or_rewritten(self):
        value={'role':'security'}
        with patch.object(Path,'exists',return_value=True),patch.object(cm,'verify',side_effect=cm.Refused('partial')),patch.object(cm,'write_new') as write:
            with self.assertRaises(cm.Refused):cm.install(value,{})
            write.assert_not_called()

    def test_symlink_final_file_is_never_followed(self):
        with patch.object(cm.os,'open') as opened:
            opened.side_effect=OSError('untrusted final file')
            # Use a real trusted root parent so the read reaches O_NOFOLLOW.
            with self.assertRaises(OSError):cm.trusted_read(Path('/usr/lib/capstone-certificate-nonexistent'))
            self.assertTrue(opened.call_args.args[1]&cm.os.O_NOFOLLOW)

    def test_failed_initial_probe_never_enables_timer_or_writes_complete_receipt(self):
        value={'spec':{'certificate':'/etc/public.crt','domain':'lab.example.org'},'files':{}}
        class Meta:st_gid=0;st_mode=0o100444
        with patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'stat',return_value=Meta()),patch.object(cm,'directory'),\
             patch.object(cm,'trusted_read',side_effect=[b'PUBLIC CERT',cm.canonical({'observed_at_utc':'2026-01-01T00:00:00Z','domain':'lab.example.org','probe_status':'unavailable'})]),\
             patch.object(cm,'write_new') as write,patch.object(cm,'run') as run:
            with self.assertRaises(cm.Refused):cm.install(value,{})
            self.assertNotIn(['/usr/bin/systemctl','enable','--now',cm.TIMER.name],[call.args[0] for call in run.call_args_list])
            self.assertNotIn(cm.INSTALL_STATE/'receipt.json',[call.args[0] for call in write.call_args_list])

    def test_private_key_material_in_public_cert_input_is_rejected_before_any_write(self):
        value={'spec':{'certificate':'/etc/public.crt'}}
        with patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(cm,'trusted_read',return_value=b'PUBLIC CERT PRIVATE KEY'),patch.object(cm,'write_new') as write:
            with self.assertRaises(cm.Refused):cm.install(value,{})
            write.assert_not_called()

if __name__=='__main__':unittest.main()
