import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('response_entry',Path(__file__).parents[1]/'response_entrypoint.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Boundary(unittest.TestCase):
    def test_unprivileged_identity_or_extra_arguments_refused(self):
        for uid,argv in ((1001,['entry']), (0,['entry','list'])):
            with patch.object(m.os,'geteuid',return_value=uid),patch.object(m.sys,'argv',argv),self.assertRaises(ValueError):
                m.main()

    def test_caller_environment_cannot_replace_root_helper_or_token(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'response.json').write_text(json.dumps({
                'RESP_BROKER_URL':'https://10.200.10.10:8445','RESP_BROKER_TOKEN':'r'*48}))
            observed=[]
            with patch.object(m,'ROOT',root),patch.object(m,'trusted',side_effect=lambda p,**kw:p),\
                    patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'argv',['entry']),\
                    patch.dict(os.environ,{'RESP_AGENT_BLOCK':'/tmp/attacker','RESP_BROKER_TOKEN':'attacker'},clear=True),\
                    patch.object(m.runpy,'run_path',side_effect=lambda *a,**kw:observed.append(dict(os.environ))),\
                    patch.object(m,'set_limits'),\
                    patch.object(m.urllib.request,'install_opener'):
                m.main()
            self.assertEqual(observed[0]['RESP_AGENT_BLOCK'],'/usr/local/libexec/capstone-response-apply')
            self.assertEqual(observed[0]['RESP_BROKER_TOKEN'],'r'*48)

    def test_private_config_cannot_enable_http_or_select_an_executable(self):
        for change in ({'RESP_BROKER_URL':'http://10.200.10.10:8090'}, {'RESP_AGENT_BLOCK':'/bin/sh'}):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);config={'RESP_BROKER_URL':'https://10.200.10.10:8445','RESP_BROKER_TOKEN':'r'*48,**change}
                (root/'response.json').write_text(json.dumps(config))
                with patch.object(m,'ROOT',root),patch.object(m,'trusted',side_effect=lambda p,**kw:p),\
                        patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'argv',['entry']),\
                        patch.object(m,'set_limits'),self.assertRaises(ValueError):m.main()

    def test_redirects_never_forward_broker_credentials(self):
        with self.assertRaises(ValueError):m.NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_privileged_process_and_children_have_bounded_resources(self):
        with patch.object(m.resource,'setrlimit') as limits:
            m.set_limits()
        selected={args.args[0]:args.args[1] for args in limits.call_args_list}
        self.assertEqual(selected[m.resource.RLIMIT_AS],(512*1024*1024,)*2)
        self.assertEqual(selected[m.resource.RLIMIT_CORE],(0,0))

    def test_oversized_protocol_request_closes_without_echoing_payload(self):
        server=Path(__file__).resolve().parents[2]/'infra/mcp/response-mcp.py'
        result=subprocess.run([sys.executable,'-I','-B',str(server)],input='X'*65537+'\n',
            capture_output=True,text=True,timeout=5,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,'')
        self.assertIn('bounded protocol input',result.stderr)
        self.assertNotIn('X'*100,result.stderr)


if __name__=='__main__':unittest.main()
