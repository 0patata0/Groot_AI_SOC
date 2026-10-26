"""Cross-component fresh-install scope; no packages, network or model."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

class InstallContract(unittest.TestCase):
    def test_profiles_cover_runtime_scope_and_keep_protected_calls_separate(self):
        installer=load('trial_install','deployment/ollama_trial.py')
        policy=load('trial_policy','infra/ollama-trial/policy.py')
        self.assertEqual(set(installer.PROFILES),set(policy.capabilities('read-only')))
        self.assertEqual(set(installer.PARITY_PROFILES),set(policy.capabilities('hermes-parity')))
        for name,args in installer.PROFILES.items():self.assertEqual(list(args),policy.PROFILES[name])
        for server,names in policy.capabilities('read-only').items():
            for name in names:self.assertFalse(policy.protected(server,name))
        self.assertIn('get_wazuh_sca_checks',policy.capabilities('read-only')['security-events'])
        self.assertEqual(sum(map(len,policy.capabilities('read-only').values())),28)
        self.assertEqual(sum(map(len,policy.capabilities('hermes-parity').values())),37)

if __name__=='__main__':unittest.main()
