import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('web_security',ROOT/'deployment/web_security.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)


class WebPolicyTests(unittest.TestCase):
    def test_public_UI_and_labs_cannot_skip_WAF_but_internal_cookie_exchange_remains(self):
        text=(ROOT/'infra/groot-c/offline-labs/nginx-log4shell-server.conf').read_text()
        self.assertEqual(text.count('proxy_pass http://172.18.0.2:8080;'),4)
        self.assertNotIn('proxy_pass http://10.200.10.20:80/_offline-labs/;',text)
        self.assertEqual(text.count('proxy_set_header X-Capstone-Lab-Mode enforce;'),4)
        self.assertIn('internal;',text)
        self.assertIn('proxy_pass_request_body off;',text)
        self.assertIn('location = /log4shell/api/gateway-session { return 404; }',text)

    def test_proxy_changes_only_one_vhost_and_refuses_duplicate_or_direct_source(self):
        text=(ROOT/'infra/groot-a/chatproxy.nginx.conf').read_text()
        template=(ROOT/'infra/groot-c/offline-labs/nginx-log4shell-server.conf').read_text()
        self.assertEqual(w.proxy_candidate(text,template),text)
        for altered in (template+'\nserver_name log4shell.grootlab.duckdns.org;',
                        template.replace('proxy_pass http://172.18.0.2:8080;','proxy_pass http://10.200.10.20:80/_offline-labs/;',1)):
            with self.assertRaises(ValueError):w.proxy_candidate(text,altered)
        self.assertIn('allow 192.168.16.231;',w.proxy_candidate(text,template))
        self.assertIn('server_name chat.grootlab.duckdns.org;',w.proxy_candidate(text,template))

    def test_retired_request_filter_exemption_is_not_replaced_by_blanket_allow(self):
        policy=(ROOT/'infra/groot-c/offline-labs/REQUEST-900-CAPSTONE-LABS.conf').read_text()
        self.assertNotIn('ctl:ruleEngine=DetectionOnly',policy)
        self.assertNotIn('id:10031,',policy)
        self.assertIn('ctl:ruleEngine=On',policy)
        self.assertNotIn('ctl:ruleRemoveByTag',policy)
        self.assertNotIn('ctl:auditEngine=Off',policy)

    def test_exact_digest_required_before_mutation(self):
        with patch.object(w,'artifact',return_value={'plan_sha256':'approved'}),patch.object(w,'run') as run,patch.object(w,'set_sources') as write:
            with self.assertRaisesRegex(ValueError,'exact_prepared_plan'):w.apply(Path('/unused'),'different')
            run.assert_not_called();write.assert_not_called()

    def test_original_recovery_and_confirmed_race_do_not_restart(self):
        m={'role':'c','files':{'/fixed':{'before':{'sha256':'same'}}}}
        with patch.object(w,'artifact',return_value=m),patch.object(w,'validate_files'),patch.object(w,'same',return_value=True),patch.object(w,'file_info'),patch.object(w,'run') as run,patch.object(w,'activate') as restart:
            self.assertEqual(w.recover(Path('/missing'))['status'],'already_original')
            run.assert_not_called();restart.assert_not_called()
        with patch.object(w,'artifact',return_value=m),patch.object(Path,'exists',return_value=True),patch.object(w,'validate_files') as check,patch.object(w,'activate') as restart:
            self.assertEqual(w.recover(Path('/unused'))['status'],'confirmed_recovery_noop')
            check.assert_not_called();restart.assert_not_called()

    def test_drift_refusal_precedes_restoration(self):
        with patch.object(w,'artifact',return_value={'role':'c'}),patch.object(w,'validate_files',side_effect=ValueError('drift')),patch.object(w,'set_sources') as write,patch.object(w,'activate') as restart:
            with self.assertRaisesRegex(ValueError,'drift'):w.recover(Path('/missing'))
            write.assert_not_called();restart.assert_not_called()


if __name__=='__main__':unittest.main()
