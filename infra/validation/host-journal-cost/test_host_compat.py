"""Run frozen host contract tests with the new Linux-fd I/O dependency mocked.

The frozen parent test source is unchanged. Real Linux/proc and partitioning
are covered separately by test_partitions and the real-host probes.
"""
from pathlib import Path
import hashlib,importlib.util,os,sys,unittest
from unittest.mock import patch
P=Path(os.environ['SOC_FROZEN_HOST_TEST']);expected='1ea2bc604fac5a3a6b1bd4f91652ab2997fadbafb07ed7737d361c3a2609823b'
assert P.is_file() and hashlib.sha256(P.read_bytes()).hexdigest()==expected
spec=importlib.util.spec_from_file_location('frozen_host_contract_compat',P);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
original=m.FixedHost.setUp
def setup(self):
 original(self)
 mock=patch.object(m.n,'journal_fds',return_value={});mock.start();self.addCleanup(mock.stop)
m.FixedHost.setUp=setup
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(m));raise SystemExit(0 if result.wasSuccessful() else 1)
