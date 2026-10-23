import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('internal_tls',Path(__file__).parents[1]/'internal_tls.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Transport(unittest.TestCase):
    def test_only_fixed_tls_frontends_and_same_host_plaintext_backends(self):
        text=m.nginx_configuration('10.200.10.10','10.200.10.1').decode()
        self.assertIn('listen 10.200.10.10:8444 ssl;',text)
        self.assertIn('listen 10.200.10.10:8445 ssl;',text)
        self.assertIn('proxy_pass http://10.200.10.10:8065;',text)
        self.assertIn('proxy_pass http://127.0.0.1:8090;',text)
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;',text)

    def test_only_security_edge_can_supply_client_address(self):
        text=m.nginx_configuration('10.200.10.10','10.200.10.1').decode()
        self.assertIn('set_real_ip_from 10.200.10.1;',text)
        self.assertNotIn('$proxy_add_x_forwarded_for',text)
        self.assertEqual(text.count('proxy_set_header X-Forwarded-For $remote_addr;'),2)
        self.assertEqual(text.count('proxy_set_header Upgrade $http_upgrade;'),2)

    def test_locked_account_has_no_capabilities_or_writable_system(self):
        text=m.unit().decode()
        for required in ('User=capstone-tls','NoNewPrivileges=yes','ProtectSystem=strict',
                         'CapabilityBoundingSet=\n','RuntimeDirectoryMode=0700'):
            self.assertIn(required,text)

    def test_external_or_injected_listener_is_refused(self):
        for host in ('8.8.8.8','10.200.10.10; return 200'):
            with self.assertRaises(ValueError):m.nginx_configuration(host,'10.200.10.1')


if __name__=='__main__':unittest.main()
