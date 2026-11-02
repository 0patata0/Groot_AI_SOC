"""Execute only pure shell endpoint helpers with mock Docker/F; no network."""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProxyBoundary(unittest.TestCase):
    def rule(self, source="172.18.0.3", destination="172.18.0.2", split=False):
        raw = (ROOT/'infra/groot-a/fw-v2/capstone-nat.sh').read_text()
        helper = raw.split('# BEGIN LOG4SHELL_TLS_WAF_HELPERS',1)[1].split('# END LOG4SHELL_TLS_WAF_HELPERS',1)[0]
        # Endpoint discovery is independently retained; substitute its bounded
        # result to test the allow/omit boundary without sourcing the installer.
        script = helper + '\ncapstone_tls_endpoint(){\n'
        script += ' if [[ $1 == chatproxy ]]; then printf "%s\\n" "' + source + ' br-fixture";\n'
        script += ' else printf "%s\\n" "' + destination + (' br-other' if split else ' br-fixture') + '"; fi\n}\n'
        script += 'F(){ printf "%s\\n" "$@"; }\ncapstone_log4shell_tls_waf_forward\n'
        r = subprocess.run(['bash','-c',script],capture_output=True,text=True,timeout=3)
        self.assertEqual(r.returncode,0)
        return r.stdout.splitlines()

    def test_only_fixed_same_bridge_source_destination_and_original_port(self):
        rule=self.rule()
        self.assertIn('172.18.0.3/32',rule);self.assertIn('172.18.0.2/32',rule)
        self.assertEqual(rule[rule.index('--dport')+1],'8080')
        self.assertEqual(rule[rule.index('--ctorigdstport')+1],'8080')
        self.assertEqual(rule[rule.index('--ctstate')+1],'NEW')
        self.assertNotIn('br-+',rule);self.assertNotIn('192.168.16.230',rule)
        for args in ({'source':'172.18.0.1'},{'destination':'172.18.0.4'},{'split':True}):
            with self.subTest(args=args):self.assertEqual(self.rule(**args),[])

    def test_real_ip_is_server_scoped_before_location_and_gateway_not_trusted(self):
        raw=(ROOT/'infra/groot-c/offline-labs/waf-log4shell-server.conf').read_text()
        before=raw.split('    location ',1)[0]
        self.assertIn('set_real_ip_from 172.18.0.3;',before)
        self.assertEqual(raw.count('set_real_ip_from '),1)
        self.assertNotIn('172.18.0.1',raw)
        proxy=(ROOT/'infra/groot-c/offline-labs/nginx-log4shell-server.conf').read_text()
        self.assertEqual(proxy.count('proxy_pass http://172.18.0.2:8080;'),3)
        self.assertEqual(proxy.count('proxy_set_header X-Capstone-Lab-Client "$remote_addr:$remote_port";'),3)


if __name__ == '__main__':unittest.main()
