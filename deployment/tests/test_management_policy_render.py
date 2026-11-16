import importlib.util
from pathlib import Path
import subprocess
import unittest

s=importlib.util.spec_from_file_location('test_policy_render',Path(__file__).parents[1]/'management_policy_render.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
SOURCE=Path(__file__).parents[2]/'infra/groot-a/fw-v2/capstone-nat.sh'


class LoaderTests(unittest.TestCase):
    def test_actual_native_source_prepares_multiple_addresses_and_bash_syntax(self):
        before=SOURCE.read_bytes();result=m.native_loader(before,['192.168.16.231/32','198.51.100.0/24'])
        self.assertEqual(m.current_native_sources(result),['192.168.16.231/32','198.51.100.0/24'])
        q=subprocess.run(['bash','-n'],input=result,capture_output=True)
        self.assertEqual(q.returncode,0,q.stderr.decode())
        self.assertNotIn(b'$MGMT_DNAT_SRC',result)
        self.assertEqual(before,SOURCE.read_bytes())

    def test_only_fixed_assignment_forward_arguments_and_log_change(self):
        before=SOURCE.read_text();after=m.native_loader(before.encode(),['192.168.16.231/32','198.51.100.0/24']).decode()
        # The egress rules and agent_block persistence are unchanged byte spans.
        start=before.index('  # int -> ext :');end=before.index('# 6)')
        self.assertIn(before[start:end],after)
        self.assertIn('NAT_HELPER="/usr/local/libexec/capstone-firewall-nat.py"',after)

    def test_reconcile_candidate_is_idempotent_and_subsequent_source_edit_is_local(self):
        first=m.native_loader(SOURCE.read_bytes(),['192.168.16.231/32','198.51.100.0/24'])
        self.assertEqual(first,m.native_loader(first,['192.168.16.231/32','198.51.100.0/24']))
        second=m.native_loader(first,['192.168.16.231/32'])
        self.assertEqual(second.decode().replace(m.block(['192.168.16.231/32']),m.block(['192.168.16.231/32','198.51.100.0/24'])),first.decode())

    def test_block_tampering_or_duplicate_markers_refused(self):
        candidate=m.native_loader(SOURCE.read_bytes(),['192.168.16.231/32'])
        for altered in (candidate+b'\n'+m.BEGIN.encode()+b'\n',
                        candidate.replace(b'MGMT_DNAT_SOURCES=(',b'MGMT_DNAT_SOURCES=(; echo nope ')):
            with self.assertRaises(ValueError):m.native_loader(altered,['198.51.100.0/24'])

    def test_unknown_old_scalar_use_is_not_silently_rewritten(self):
        raw=SOURCE.read_bytes()+b'printf "%s" "$MGMT_DNAT_SRC"\n'
        with self.assertRaisesRegex(ValueError,'unknown_scalar_use'):
            m.native_loader(raw,['198.51.100.0/24'])

    def test_inputs_cannot_inject_shell_or_widen_host_bits(self):
        for value in ['$(touch /tmp/nope)','192.0.2.21/24','0.0.0.0/0','192.0.2.1/32;true']:
            with self.subTest(value=value),self.assertRaises(ValueError):
                m.native_loader(SOURCE.read_bytes(),[value])

    def test_array_passes_each_network_as_a_separate_helper_argument(self):
        values=['192.168.16.231/32','198.51.100.0/24']
        # Execute just fixed variable/array assignments, never the gateway loader.
        script=m.block(values)+'\n'+m.ARGUMENTS+'printf "%s\\n" "${NAT_ARGS[@]}"\n'
        q=subprocess.run(['bash'],input=script,text=True,capture_output=True,timeout=5)
        self.assertEqual(q.returncode,0,q.stderr)
        self.assertEqual(q.stdout.splitlines(),['--management-source',values[0],'--management-source',values[1]])


if __name__=='__main__':unittest.main()
