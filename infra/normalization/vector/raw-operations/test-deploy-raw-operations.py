#!/usr/bin/env python3
"""Pure preparation contracts. No Docker, services, mounts or operating paths."""
import importlib.util
import copy
import io
from contextlib import nullcontext, ExitStack, redirect_stdout
import json
import os
import tempfile
import sys
from unittest.mock import patch, Mock
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('raw_deployment', HERE / 'deploy-raw-operations-a.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
REPO = HERE.parents[2]
FIXTURES = Path(os.environ['CAPSTONE_RAW_TEST_FIXTURES']) if 'CAPSTONE_RAW_TEST_FIXTURES' in os.environ else None


class PreparationContracts(unittest.TestCase):
    def test_actual_pinned_logrotate_preserves_comments_and_options(self):
        raw = ((FIXTURES / 'logrotate-capstone-secstack') if FIXTURES else (REPO / 'groot-a/logrotate-capstone-secstack')).read_bytes()
        self.assertEqual(deploy.sha(raw), deploy.HOST['logrotate'][1])
        fixed = deploy.logrotate_candidate(raw)
        self.assertIn(b'eve.json', fixed)  # Historical explanatory comment retained.
        executable = [s.strip() for s in fixed.splitlines() if s.strip() and not s.lstrip().startswith(b'#')]
        paths = executable[:4]
        self.assertEqual(paths, [str(deploy.BASE / p).encode() for p in
            ('suricata/fast.log', 'suricata/stats.log', 'suricata/suricata.log')] +
            [(str(deploy.BASE / 'modsec/capstone-access.log') + ' {').encode()])
        self.assertEqual(fixed.split(b'{', 1)[1], raw.split(b'{', 1)[1])

    def test_logrotate_rejects_second_stanza(self):
        raw = ((FIXTURES / 'logrotate-capstone-secstack') if FIXTURES else (REPO / 'groot-a/logrotate-capstone-secstack')).read_bytes()
        with self.assertRaises(deploy.Refused):
            deploy.logrotate_candidate(raw + b'/x/*.log { copytruncate }\n')

    def test_yaml_exact_changed_span(self):
        raw = b'# eve.json\noutputs:\n  - eve-log:\n      filename: eve.json # stable\n      enabled: yes\n'
        self.assertEqual(deploy.yaml_candidate(raw), raw.replace(b'filename: eve.json',
                         b'filename: capstone-managed/active.jsonl'))

    def test_yaml_ambiguous_and_crlf_rejected(self):
        for raw in (b'filename: eve.json\nfilename: eve.json\n', b'filename: eve.json\r\n',
                    b'filename: elsewhere\n'):
            with self.subTest(raw=raw), self.assertRaises(deploy.Refused):
                deploy.yaml_candidate(raw)

    def test_override_comments_only(self):
        raw = b'# original comment\n\n'
        changed = deploy.override_candidate(raw)
        self.assertEqual(changed[:len(raw)], raw)
        self.assertEqual(changed.count(b'Include '), 1)
        with self.assertRaises(deploy.Refused):
            deploy.override_candidate(raw + b'SecRuleEngine DetectionOnly\n')

    def environment(self):
        return (b'# literal values, never sourced as shell\nCAPSTONE_SENSOR=GROOT_A\n' +
                b'WAF_INSTANCE_ID=' + b'1' * 64 + b'\nWAF_CONFIG_SHA256=' + b'2' * 64 +
                b'\nWAF_DEPLOYMENT_BINDING=' + b'3' * 64 + b'\nWAF_AUDIT_PATH=' +
                str(deploy.BASE / 'modsec/audit.log').encode() + b'\nWAF_ACCESS_PATH=' +
                str(deploy.BASE / 'modsec/capstone-access.log').encode() + b'\n')

    def test_environment_changes_only_three_binding_values(self):
        raw = self.environment()
        result = deploy.environment_candidate(raw, b'producer\n')
        before = raw.splitlines(); after = result.splitlines()
        changed = [a.split(b'=', 1)[0] for a, b in zip(before, after) if a != b]
        self.assertEqual(changed, [b'WAF_INSTANCE_ID', b'WAF_CONFIG_SHA256', b'WAF_DEPLOYMENT_BINDING'])
        self.assertEqual(before[-1], after[-1])

    def test_environment_duplicate_and_injection_rejected(self):
        for raw in (self.environment() + b'WAF_CONFIG_SHA256=' + b'2' * 64 + b'\n',
                    self.environment().replace(b'WAF_INSTANCE_ID=' + b'1' * 64,
                                               b'WAF_INSTANCE_ID=$(invalid)')):
            with self.subTest(raw=raw), self.assertRaises(deploy.Refused):
                deploy.environment_candidate(raw, b'producer')

    def test_manifest_v2_preserves_old_audit_provenance(self):
        raw = ((FIXTURES / 'deployment.json') if FIXTURES else (HERE.parent / 'waf-producer/deployment.json')).read_bytes()
        before = deploy.parse(raw)
        after = deploy.parse(deploy.waf_manifest_candidate(raw, b'new producer'))
        self.assertEqual(after['schema'], 'waf-producer-deployment-2')
        self.assertEqual(after['schema_version'], 2)
        self.assertEqual(after['time_policy'], 'context-created-fixed-offset-v2')
        changed = {'schema', 'schema_version', 'time_policy', 'configuration_sha256', 'deployment_binding'}
        self.assertEqual({k: v for k, v in before.items() if k not in changed},
                         {k: v for k, v in after.items() if k not in changed})

    def test_manifest_wrong_container_and_duplicate_key_refused(self):
        raw = ((FIXTURES / 'deployment.json') if FIXTURES else (HERE.parent / 'waf-producer/deployment.json')).read_bytes()
        value = json.loads(raw); value['instance_id'] = '0' * 64
        with self.assertRaises(deploy.Refused):
            deploy.waf_manifest_candidate(json.dumps(value).encode(), b'new')
        with self.assertRaises(deploy.Refused):
            deploy.parse(b'{"schema":1,"schema":2}')

    def test_no_nonfinite_json(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(deploy.Refused):
                deploy.parse(raw)

    def test_shadow_is_private_read_only_base_without_service_signal(self):
        source = deploy.SHADOW_SCRIPT
        self.assertLess(source.index('mount -t proc -o ro'), source.index('findmnt --submounts'))
        self.assertIn('[[ $target != /proc && $target != /proc/* ]] || continue', source)
        self.assertLess(source.index('remount,bind,ro'), source.index('parts=(var/log run)'))
        self.assertIn('[[ $engine != waf ]] || parts+=(var/cache/nginx)', source)
        self.assertLess(source.index('parts+=(var/cache/nginx)'), source.index('parts+=(tmp)'))
        self.assertIn('private_root_not_readonly', source)
        self.assertIn('private_proc_not_readonly', source)
        self.assertIn('nginx -t -c', source)
        self.assertIn('suricata -T -c', source)
        self.assertNotIn('systemctl', source)
        self.assertNotIn('kill ', source)

    def test_visible_mount_id_selects_new_ro_and_rejects_hidden_rw(self):
        # The native proc mount listing really contains both rows. Select by
        # opened-FD mnt_id, never by first/last or the mountpoint name alone.
        program = deploy.SHADOW_SCRIPT.split('/usr/bin/awk -v wanted="$mount_id" -v point="$point" ', 1)[1]
        program = program.split("'", 2)[1]
        rows = b'362 239 0:39 / /proc rw,nosuid - proc proc rw\n562 362 0:99 / /proc ro,nosuid - proc proc ro\n'
        for mount_id, expected in (('562', 0), ('362', 1), ('999', 1)):
            with self.subTest(mount_id=mount_id):
                result = subprocess.run(['/usr/bin/awk', '-v', 'wanted=' + mount_id,
                                         '-v', 'point=/proc', program], input=rows, capture_output=True)
                self.assertEqual(result.returncode, expected)
        duplicate = subprocess.run(['/usr/bin/awk', '-v', 'wanted=562', '-v', 'point=/proc', program],
                                   input=rows + rows.splitlines(keepends=True)[1], capture_output=True)
        self.assertEqual(duplicate.returncode, 1)


cut_spec = importlib.util.spec_from_file_location('raw_cutover', HERE / 'cutover-raw-operations-a.py')
cut = importlib.util.module_from_spec(cut_spec)
cut_spec.loader.exec_module(cut)


def ledger(phase='waf_writer_switched', operation=None, armed=False):
    value = {'phase': phase, 'sequence': 4, 'boot_id': 'b' * 32, 'plan_sha256': 'f' * 64,
             'containers': {}, 'completed': [], 'intent': None}
    if operation:
        value['intent'] = {'operation': operation, 'signal_armed': armed, 'metadata': {},
                           'automatic_signal_replay_allowed': False}
    return value, cut.p.canonical(value), {}


def fake_commit(old, value):
    return value, cut.p.canonical(value), {}


def vector_status(active=False):
    return {'ActiveState': 'active' if active else 'inactive', 'Result': 'success',
            'ExecMainStatus': '0', 'ExecMainStartTimestampMonotonic': '12345',
            'InvocationID': 'a' * 32 if active else ''}


class CutoverPolicyContracts(unittest.TestCase):
    def test_invalid_cli_refuses_before_any_host_or_phase_mutation(self):
        for args in ([], ['invalid'], ['apply-legacy'], ['inspect', 'f' * 64, 'extra']):
            result = subprocess.run([sys.executable, '-B', str(HERE / 'cutover-raw-operations-a.py'),
                                     *args], capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['reason'], 'phase_not_implemented_or_invalid')

    def test_first_inspect_never_creates_ledger(self):
        output=io.StringIO()
        with patch.object(sys,'argv',['cutover','inspect','f'*64]), patch.object(sys,'platform','linux'), \
             patch.object(os,'geteuid',return_value=0), patch.object(Path,'read_text',return_value=cut.p.MID), \
             patch.object(cut.p,'shared_lock',return_value=nullcontext()), \
             patch.object(cut,'load_plan',return_value=({},{})) as load, \
             patch.object(os.path,'lexists',return_value=False), patch.object(cut,'new_ledger') as create, \
             redirect_stdout(output):
            cut.main()
        create.assert_not_called();load.assert_called_once_with('f'*64,inspection=True)
        self.assertEqual(json.loads(output.getvalue())['status'],'prepared_not_started')

    def test_resume_keeps_first_intent_metadata(self):
        old = ledger(operation='prepare-readers')
        old[0]['intent']['metadata'] = {'frozen': 'first'}
        with patch.object(cut, 'ledger_commit') as commit:
            self.assertIs(cut.begin(old, 'prepare-readers', {'frozen': 'later'}), old)
            commit.assert_not_called()

    def test_scanner_baseline_requires_live_and_ansible_mode_0755(self):
        expected=[]
        def snapshot(path,*args,**kwargs):
            if Path(path)==cut.SCANNER: expected.append(kwargs.get('expected'))
            return b'fixture',{'uid':0,'gid':0,'mode':0o400}
        before={'boot_id':'b'*32,'containers':{}}
        with patch.object(cut.p,'snapshot',side_effect=snapshot), patch.object(cut,'durable_create'), \
             patch.object(cut,'ensure_directory'), patch.object(cut,'read_json',return_value=({},b'',{})):
            cut.new_ledger('f'*64,before)
        self.assertEqual(expected,[(cut.SCANNER_V1,0,0,0o755)])

    def test_release_rechecks_scanner_mode_0755(self):
        captured=[]
        def snapshot(path,*args,**kwargs):
            if Path(path)==cut.SCANNER: captured.append(kwargs['expected'])
            return b'fixed',{}
        plan={'candidate_sha256':{'waf_audit_context':'a'*64},
              'source_sha256':{'raw-line-scan-v2.sh':'b'*64}}
        with patch.object(cut,'read_json',return_value=({},b'{}\n',{})), \
             patch.object(cut,'runtime_artifact',return_value=b'fixed'), \
             patch.object(cut.p,'snapshot',side_effect=snapshot):
            cut.release_proof(ledger(),plan)
        self.assertEqual(captured,[('b'*64,0,0,0o755)])

    def test_different_pending_operation_refuses(self):
        old = ledger(operation='apply-readers')
        with self.assertRaises(cut.p.Refused):
            cut.begin(old, 'prepare-readers')

    def test_signal_intent_once_and_never_rearms(self):
        old = ledger(operation='prepare-readers')
        with patch.object(cut, 'ledger_commit', side_effect=fake_commit) as commit:
            armed = cut.arm_signal(old)
            self.assertTrue(armed[0]['intent']['signal_armed'])
            self.assertFalse(armed[0]['intent']['automatic_signal_replay_allowed'])
            with self.assertRaises(cut.p.Refused):
                cut.arm_signal(armed)
            self.assertEqual(commit.call_count, 1)

    def test_pause_requires_exact_invocation_start_and_clean_result(self):
        recorded = vector_status(True)
        self.assertTrue(cut.pause_is_owned(vector_status(), recorded))
        for key, value in (('ActiveState', 'active'), ('Result', 'timeout'), ('ExecMainStatus', '1'),
                           ('ExecMainStartTimestampMonotonic', '12346'), ('InvocationID', 'b' * 32)):
            changed = dict(vector_status(), **{key: value})
            self.assertFalse(cut.pause_is_owned(changed, recorded), key)

    def test_finish_failure_after_successful_stop_resumes_without_second_signal(self):
        old = ledger(operation='prepare-readers', armed=True)
        proof = {'vector_before_stop': vector_status(True), 'old_source': {'bytes': 5},
                 'old_source_sha256': 'c' * 64, 'writer': {}, 'access_prefix_bytes': 5}
        old[0]['intent']['metadata'] = proof
        info = {'uid': 0, 'gid': 0, 'mode': 0o400, 'bytes': 5}
        with patch.object(cut, 'logrotate_lock', return_value=nullcontext()), \
             patch.object(cut, 'protected'), patch.object(cut, 'unit_status', return_value=vector_status()), \
             patch.object(cut, 'old_reader_proofs', return_value=(info, {'offset':5}, {'offset':5}, {'offset':5})), \
             patch.object(cut, 'gate', return_value={'reason':'different_prefix'}), \
             patch.object(cut, 'distinct_prefix', return_value={'inode': 2}), \
             patch.object(cut, 'logged_command') as command, \
             patch.object(cut, 'finish', side_effect=lambda old, op, result: result):
            result = cut.prepare_readers({}, {}, old)
            command.assert_not_called()
            self.assertTrue(result['both_sources_eof_before_grace'])

    def test_armed_active_stop_is_uncertain_not_reissued(self):
        old = ledger(operation='prepare-readers', armed=True)
        old[0]['intent']['metadata'] = {'vector_before_stop': vector_status(True)}
        with patch.object(cut, 'logrotate_lock', return_value=nullcontext()), patch.object(cut, 'protected'), \
             patch.object(cut, 'unit_status', return_value=vector_status(True)), \
             patch.object(cut, 'logged_command') as command, self.assertRaises(cut.p.Refused):
            cut.prepare_readers({}, {}, old)
        command.assert_not_called()

    def test_frozen_bootstrap_preserves_v1_old_v2_pending_and_actual_stop(self):
        proof = {'old_source': {'device':1,'inode':2,'bytes':100},
                 'pending_source': {'device':1,'inode':3},
                 'writer': {'pid':42,'start_ticks':'123'}, 'old_source_sha256':'a'*64,
                 'vector_before_stop':vector_status(True),
                 'publication':{'reason':'different_prefix','prefix_sha1':'b'*40,'stored_sha1':'c'*40,
                                'offset':100,'source_identity':{'bytes':55},'checkpoint_sha256':'d'*64},
                 'vector_eof':{'offset':100,'checkpoint_sha256':'e'*64},
                 'wazuh_eof':{'offset':100,'stored_sha1':'c'*40,'checkpoint_sha256':'d'*64}}
        plan = {'candidate_sha256':{key: 'f'*64 for key in
                ('vector','environment','suricata_yaml','audit_path','waf_override','waf_producer')}}
        suri, waf, marker = cut.bootstrap_states(plan, ledger()[0], proof)
        self.assertEqual(suri['phase'], 'active')
        self.assertEqual((waf['current']['number'],waf['pending']['number'],waf['phase']), (0,1,'publish_pending'))
        self.assertNotEqual(waf['current']['writer_config_sha256'],waf['pending']['writer_config_sha256'])
        self.assertEqual(marker['state_sha256'], cut.p.sha(cut.p.canonical(waf)))
        self.assertEqual(marker['invocation_id'], 'a'*32)
        self.assertEqual(marker['start_usec'], '12345')
        self.assertEqual(waf['proof']['readers_drained']['vector_offset'],100)

    def test_boot_inspection_is_read_only_and_mutation_refuses_new_boot(self):
        source=b'fixture'
        value=ledger()[0]; value['cutover_sha256']=cut.p.sha(source)
        with patch.object(cut,'read_json',return_value=(value,cut.p.canonical(value),{})), \
             patch.object(cut.p,'snapshot',return_value=(source,{})), \
             patch.object(Path,'read_text',return_value='c'*32):
            self.assertEqual(cut.ledger_read('f'*64,inspection=True)[0],value)
            with self.assertRaises(cut.p.Refused): cut.ledger_read('f'*64)


class ReaderTransactionContracts(unittest.TestCase):
    """Real phase functions with deterministic crash points; OS adapters mocked.

    Separate NativePublicationContracts exercise actual Linux file/link/fsync
    operations. These tests never claim a real daemon restart/cold boot.
    """
    def test_partial_runtime_config_and_state_replay_uses_frozen_bootstrap(self):
        for fail_suffix in ('runtime/coordinator.sh', 'host-vector', 'state/suricata/state.json'):
            with self.subTest(fail_suffix=fail_suffix), ExitStack() as stack:
                root=Path('/synthetic'); runtime=root/'runtime'; state=root/'state'; backup=root/'backup'
                files={}; dirs=set(); injected=[False]; commits=[]
                original=ledger('readers_paused')
                proof={'vector_before_stop':vector_status(True),'pending_source':{'device':1,'inode':2}}
                original[0]['completed']=[{'operation':'prepare-readers','result':proof}]
                suri={'engine':'suricata'}; waf={'engine':'modsecurity','pending':{'device':1,'inode':2}}
                marker={'state_sha256':cut.p.sha(cut.p.canonical(waf)),'invocation_id':'a'*32}
                plan={'candidate_sha256':{},'source_sha256':{}}
                def ensure(path,mode=0o700): dirs.add(Path(path))
                def publish(path,raw,mode=0o400):
                    path=Path(path)
                    if path in files and files[path]!=raw: raise cut.p.Refused('fixture_conflict')
                    files[path]=raw
                    if str(path).endswith(fail_suffix) and not injected[0]:
                        injected[0]=True; raise OSError('fixture_crash_after_publication')
                def replace(path,raw,*args):
                    if Path(path)==root/'scanner': self.assertEqual(args[-3:],(0,0,0o755))
                    publish(path,raw)
                def entries(path): return iter(sorted(p for p in set(files)|dirs if p.parent==path))
                def commit(old,new):
                    result=fake_commit(old,new);commits.append(result);return result
                for key,value in (('RUNTIME',runtime),('STATE',state),('BACKUP',backup),('CONFIG',root/'config')):
                    stack.enter_context(patch.object(cut.p,key,value))
                host={key:(str(root/('host-'+key)),'old',0,0,0o600) for key in
                      ('vector','environment','waf_binding','line_binding')}
                stack.enter_context(patch.object(cut.p,'HOST',host))
                stack.enter_context(patch.object(cut,'SCANNER',root/'scanner'))
                stack.enter_context(patch.object(cut,'protected'))
                stack.enter_context(patch.object(cut,'sealed_bootstrap_proof',return_value=proof))
                build=stack.enter_context(patch.object(cut,'bootstrap_states',return_value=(suri,waf,marker)))
                stack.enter_context(patch.object(cut,'ledger_commit',side_effect=commit))
                stack.enter_context(patch.object(cut,'ensure_directory',side_effect=ensure))
                stack.enter_context(patch.object(cut,'durable_create',side_effect=publish))
                stack.enter_context(patch.object(cut,'ensure_replacement',side_effect=replace))
                stack.enter_context(patch.object(Path,'iterdir',entries))
                stack.enter_context(patch.object(cut,'runtime_artifact',side_effect=lambda name,plan:('source:'+name).encode()))
                stack.enter_context(patch.object(cut,'candidate',side_effect=lambda name,plan:('candidate:'+name).encode()))
                stack.enter_context(patch.object(cut.p,'command',return_value=(0,b'')))
                stack.enter_context(patch.object(cut,'require_barrier'))
                stack.enter_context(patch.object(cut,'unit_status',return_value=vector_status()))
                with self.assertRaises(OSError): cut.apply_readers(plan,{},original)
                self.assertTrue(injected[0]); self.assertEqual(commits[-1][0]['phase'],'readers_paused')
                frozen=copy.deepcopy(commits[-1][0]['intent']['metadata'])
                result=cut.apply_readers(plan,{},commits[-1])
                self.assertEqual(result[0]['phase'],'readers_bootstrapped')
                self.assertEqual(build.call_count,1)
                self.assertEqual(files[state/'modsecurity/state.json'],cut.p.canonical(frozen['bootstrap']['modsecurity']))
                self.assertEqual(files[state/'vector-stop-intent.json'],cut.p.canonical(frozen['bootstrap']['marker']))

    def release_fixture(self,failpoint,auto_active=False,tamper=False):
        with ExitStack() as stack:
            original=ledger('readers_bootstrapped')
            original[0]['completed']=[{'operation':'prepare-readers','result':{'vector_before_stop':vector_status(True)}}]
            record={'phase':'blocked','plan_sha256':'f'*64,'release':None}; files={}; commits=[]; calls=[]; injected=[False]
            def commit(old,new):
                result=fake_commit(old,new);commits.append(result);return result
            def read(path,*args): return copy.deepcopy(record),cut.p.canonical(record),{}
            def release(old,plan): return {'ledger_sha256':cut.p.sha(old[1]),'guard':'fixed'}
            def publish(path,raw,*args):
                if Path(path)==cut.BARRIER:
                    record.clear();record.update(cut.p.parse(raw));calls.append('release')
                    if failpoint=='release' and not injected[0]:
                        injected[0]=True;raise OSError('fixture_after_release')
                else:
                    files[str(path)]=raw;calls.append('final_dropin')
                    if failpoint=='dropin' and not injected[0]:
                        injected[0]=True;raise OSError('fixture_after_first_dropin')
            def show(argv,**kwargs):
                reader='vector' if 'capstone-vector.service' in argv else 'wazuh'
                return 0,('/usr/local/lib/capstone-raw-operations/guard.sh '+reader).encode()
            def status(unit): return vector_status(auto_active and record['phase']=='released')
            stack.enter_context(patch.object(cut,'read_json',side_effect=read))
            stack.enter_context(patch.object(cut,'release_proof',side_effect=release))
            stack.enter_context(patch.object(cut,'ledger_commit',side_effect=commit))
            stack.enter_context(patch.object(cut,'protected'))
            stack.enter_context(patch.object(cut,'unit_status',side_effect=status))
            stack.enter_context(patch.object(cut,'durable_create'))
            stack.enter_context(patch.object(cut,'unit_artifact',return_value=b'ExecStartPre=+/bin/bash /usr/local/lib/capstone-raw-operations/guard.sh vector\n'))
            commands=stack.enter_context(patch.object(cut,'logged_command',return_value=(0,b'')))
            stack.enter_context(patch.object(cut,'atomic_replace',side_effect=publish))
            stack.enter_context(patch.object(cut,'ensure_replacement',side_effect=publish))
            stack.enter_context(patch.object(cut,'require_barrier',side_effect=lambda *a,**k:copy.deepcopy(record)))
            stack.enter_context(patch.object(cut.p,'command',side_effect=show))
            with self.assertRaises(OSError): cut.install_guards({}, {}, original)
            self.assertTrue(injected[0]);self.assertEqual(record['phase'],'released')
            self.assertEqual(calls[0],'release')
            if tamper:
                record['release']['ledger_sha256']='wrong'
                before=commands.call_count
                with self.assertRaises(cut.p.Refused):cut.install_guards({}, {}, commits[-1])
                self.assertEqual(commands.call_count,before)
            else:
                result=cut.install_guards({}, {}, commits[-1])
                self.assertEqual(result[0]['phase'],'guards_installed')
                self.assertEqual(result[0]['completed'][-1]['result']['vector_active_after_release'],auto_active)
                self.assertEqual(calls.count('release'),1)
                self.assertFalse(any('start' in call.args[0] or 'stop' in call.args[0] or 'restart' in call.args[0]
                                     for call in commands.call_args_list))
    def test_crash_immediately_after_release_reuses_exact_release(self):
        self.release_fixture('release')
    def test_crash_after_first_final_dropin_retries_without_release_rewrite(self):
        self.release_fixture('dropin')
    def test_released_normal_guard_auto_active_is_accepted_without_start(self):
        self.release_fixture('release',auto_active=True)
    def test_conflicting_released_intent_refuses_before_command(self):
        self.release_fixture('release',tamper=True)


class RecoveryContracts(unittest.TestCase):
    """Narrow incident recovery, with no source checkpoint or service mutation."""
    def fixture(self):
        before={'boot_id':'b'*32, 'units':{'capstone-vector.service':{
            'InvocationID':'a'*32,'MainPID':'10','DropInPaths':''},
            'wazuh-agent.service':{'InvocationID':'c'*32}}}
        old=ledger('legacy_excluded','apply-suricata',True)
        old[0].update(sequence=6,cutover_sha256=cut.RECOVERY_PREVIOUS_SOURCE,
                      containers={'suricata':{'cid':'s','mounts':[],'process':{'pid':10}}})
        old=(old[0],cut.p.canonical(old[0]),{})
        state={'ActiveState':'active','SubState':'running','InvocationID':'d'*32,
               'MainPID':'123','Result':'success','ExecMainStatus':'0',
               'ExecMainStartTimestampMonotonic':'54321'}
        evidence={name:cut.p.canonical({'synthetic':name}) for name in
                  ('authority.json','prestart.json','timer-before.json')}
        evidence['pending.before']=b'pending\n'
        guard=b'reviewed synthetic guard\n'
        receipt={'schema_version':1,'policy':'capstone-raw-v1-recovery-1','machine_id':cut.p.MID,
            'boot_id':'b'*32,'plan_sha256':'f'*64,'before_sha256':'e'*64,
            'previous_ledger_sha256':cut.RECOVERY_PREVIOUS_LEDGER,
            'previous_cutover_sha256':cut.RECOVERY_PREVIOUS_SOURCE,'old_vector_invocation_id':'a'*32,
            'vector_after':state,'vector_start_ticks':'11223','guard_sha256':cut.p.sha(guard),
            'evidence_sha256':{k:cut.p.sha(v) for k,v in evidence.items()},'completed_at_epoch':1,
            'raw_deleted':False,'checkpoint_rewritten':False,'maintenance_rotation_repeated':False}
        authority={'schema_version':1,'policy':'capstone-v1-vector-recovery-20261015','machine_id':cut.p.MID,
            'boot_id':'b'*32,'plan_sha256':'f'*64,'ledger_sha256':cut.RECOVERY_PREVIOUS_LEDGER,
            'cutover_sha256':cut.RECOVERY_PREVIOUS_SOURCE,'prepare_sha256':cut.PREPARATION_SHA256,
            'guard_sha256':receipt['guard_sha256'],'barrier_sha256':cut.p.sha(b'blocked\n'),
            'issued_uptime_seconds':100,'expiry_uptime_seconds':200,'wazuh_pid':42,'wazuh_start_ticks':9876}
        timer={'schema_version':1,'unit':'capstone-vector-maintenance.timer','unit_sha256':cut.p.sha(b'timer\n'),
            'previous_unit_file_state':'enabled','previous_active_state':'active',
            'current_unit_file_state':'disabled','current_active_state':'inactive'}
        evidence['authority.json']=cut.p.canonical(authority)
        evidence['timer-before.json']=cut.p.canonical(timer)
        receipt['evidence_sha256'].update({k:cut.p.sha(v) for k,v in evidence.items()})
        proof={'schema_version':1,'policy':'capstone-v1-vector-recovery-20261015','status':'pass',
            'reason':'verified_v1_start_only','machine_id':cut.p.MID,'boot_id':'b'*32,
            'authority_sha256':receipt['evidence_sha256']['authority.json'],
            'guard_sha256':receipt['guard_sha256'],'plan_sha256':'f'*64,
            'ledger_sha256':cut.RECOVERY_PREVIOUS_LEDGER,'barrier_sha256':cut.p.sha(b'blocked\n'),
            'checkpoints_rewritten':False,'delivery_acknowledged':False,'read_only':True,
            'raw_current_proofs':[{'gate':'vector_current','verdict':'pass','reason':'current_offset_valid',
                'source_stable':True,'offset':5,'checkpoint_sha256':'1'*64,
                'source_identity':{'device':64512,'inode':ino,'bytes':10}}
                for ino in (1441879,1441881,1441928)],
            'output_eof_proofs':[{'path':'/var/log/capstone-vector/'+kind+'/normalized.jsonl',
                'device':1,'inode':index,'bytes':0,'fd_count':1,'position':0,'empty_native_fd':True}
                for index,kind in enumerate(('ready','evidence'),1)]}
        evidence['prestart.json']=cut.p.canonical(proof)
        receipt['evidence_sha256']['prestart.json']=cut.p.sha(evidence['prestart.json'])
        return {'before':before,'old':old,'plan':{'before_sha256':'e'*64},
                'receipt':receipt,'evidence':evidence,'guard':guard}

    def receipt_context(self, stack, fixture, receipt=None):
        value=copy.deepcopy(fixture['receipt'] if receipt is None else receipt)
        data=cut.p.canonical(value)
        stack.enter_context(patch.object(cut,'read_json',return_value=(value,data,{})))
        def snapshot(path,*args,**kwargs):
            path=Path(path)
            raw=fixture['guard'] if path.name=='v1-recovery-guard.sh' else fixture['evidence'][path.name]
            self.assertEqual(kwargs['expected'],(cut.p.sha(raw),0,0,0o400))
            return raw,{}
        stack.enter_context(patch.object(cut.p,'snapshot',side_effect=snapshot))
        return cut.p.sha(data)

    def test_recovery_overlay_changes_only_vector_and_never_mutates_before(self):
        fixture=self.fixture(); preserved=copy.deepcopy(fixture['before'])
        with ExitStack() as stack:
            digest=self.receipt_context(stack,fixture)
            value=dict(fixture['old'][0],v1_recovery={'receipt_sha256':digest,
                       'previous_ledger_sha256':cut.RECOVERY_PREVIOUS_LEDGER})
            effective=cut.effective_before(fixture['plan'],fixture['before'],value)
        self.assertEqual(fixture['before'],preserved)
        self.assertEqual(effective['units']['wazuh-agent.service'],preserved['units']['wazuh-agent.service'])
        self.assertEqual(effective['units']['capstone-vector.service']['InvocationID'],'d'*32)
        self.assertEqual(effective['units']['capstone-vector.service']['DropInPaths'],'')
        self.assertIs(cut.effective_before({},preserved,{}),preserved)

    def test_receipt_rejects_wrong_incident_original_baseline_and_status(self):
        fixture=self.fixture()
        changes=[('previous_ledger_sha256','0'*64),('previous_cutover_sha256','0'*64),
                 ('before_sha256','0'*64),('old_vector_invocation_id','0'*32),
                 ('boot_id','0'*32),('checkpoint_rewritten',True),('raw_deleted',0),
                 ('schema_version',True),('unknown','ignored')]
        for field,value in changes:
            altered=copy.deepcopy(fixture['receipt']);altered[field]=value
            with self.subTest(field=field),ExitStack() as stack:
                digest=self.receipt_context(stack,fixture,altered)
                with self.assertRaises(cut.p.Refused):
                    cut.recovery_receipt(fixture['plan'],fixture['before'],fixture['old'][0],digest)
        for field,value in [('InvocationID','a'*32),('Result','exit-code'),('MainPID','0'),('unknown','ignored')]:
            altered=copy.deepcopy(fixture['receipt']);altered['vector_after'][field]=value
            with self.subTest(status_field=field),ExitStack() as stack:
                digest=self.receipt_context(stack,fixture,altered)
                with self.assertRaises(cut.p.Refused):
                    cut.recovery_receipt(fixture['plan'],fixture['before'],fixture['old'][0],digest)

    def test_receipt_rejects_wrong_hash_and_changed_archived_pending(self):
        fixture=self.fixture()
        with ExitStack() as stack:
            self.receipt_context(stack,fixture)
            with self.assertRaises(cut.p.Refused):
                cut.recovery_receipt(fixture['plan'],fixture['before'],fixture['old'][0],'0'*64)
        fixture['evidence']['pending.before']=b'other\n'
        fixture['receipt']['evidence_sha256']['pending.before']=cut.p.sha(b'other\n')
        with ExitStack() as stack:
            digest=self.receipt_context(stack,fixture)
            with self.assertRaises(cut.p.Refused):
                cut.recovery_receipt(fixture['plan'],fixture['before'],fixture['old'][0],digest)

    def test_only_explicit_upgrade_can_read_exact_frozen_old_source(self):
        fixture=self.fixture(); value,raw,_=fixture['old']
        with patch.object(cut,'RECOVERY_PREVIOUS_LEDGER',cut.p.sha(raw)), \
             patch.object(cut,'read_json',return_value=(value,raw,{})), \
             patch.object(cut.p,'snapshot',return_value=(b'new source',{})), \
             patch.object(Path,'read_text',return_value='b'*32):
            with self.assertRaises(cut.p.Refused):cut.ledger_read('f'*64)
            self.assertEqual(cut.ledger_read('f'*64,recovery_upgrade=True)[0],value)
        with patch.object(cut,'read_json',return_value=(value,raw+b' ',{})), \
             patch.object(cut.p,'snapshot',return_value=(b'new source',{})), \
             patch.object(Path,'read_text',return_value='b'*32),self.assertRaises(cut.p.Refused):
            cut.ledger_read('f'*64,recovery_upgrade=True)

    def test_timer_disabled_inactive_and_no_active_maintenance_are_required(self):
        for timer,service,allowed in [
            (b'ActiveState=inactive\nUnitFileState=disabled\n',{'ActiveState':'failed','MainPID':'0'},True),
            (b'ActiveState=inactive\nUnitFileState=enabled\n',{'ActiveState':'failed','MainPID':'0'},False),
            (b'ActiveState=active\nUnitFileState=disabled\n',{'ActiveState':'failed','MainPID':'0'},False),
            (b'ActiveState=inactive\nUnitFileState=disabled\n',{'ActiveState':'active','MainPID':'42'},False)]:
            with self.subTest(timer=timer,service=service), \
                 patch.object(cut.p,'command',return_value=(0,timer)), \
                 patch.object(cut,'unit_status',return_value=service):
                if allowed:cut.maintenance_paused()
                else:
                    with self.assertRaises(cut.p.Refused):cut.maintenance_paused()

    def test_semantically_empty_and_crossbound_evidence_refuses_despite_valid_hash(self):
        changes=[('prestart.json',{}),('authority.json',{}),('timer-before.json',{}),
                 ('prestart.json',{'status':'refused'}),
                 ('prestart.json',{'guard_sha256':'0'*64}),
                 ('prestart.json',{'raw_current_proofs':[]}),
                 ('prestart.json',{'output_eof_proofs':[]}),
                 ('authority.json',{'prepare_sha256':'0'*64}),
                 ('authority.json',{'expiry_uptime_seconds':1001}),
                 ('timer-before.json',{'previous_unit_file_state':'disabled'}),
                 ('timer-before.json',{'current_unit_file_state':'enabled'})]
        for name,change in changes:
            fixture=self.fixture();decoded=cut.p.parse(fixture['evidence'][name])
            if change:decoded.update(change)
            else:decoded={}
            fixture['evidence'][name]=cut.p.canonical(decoded)
            fixture['receipt']['evidence_sha256'][name]=cut.p.sha(fixture['evidence'][name])
            if name=='authority.json':
                proof=cut.p.parse(fixture['evidence']['prestart.json'])
                proof['authority_sha256']=fixture['receipt']['evidence_sha256'][name]
                fixture['evidence']['prestart.json']=cut.p.canonical(proof)
                fixture['receipt']['evidence_sha256']['prestart.json']=cut.p.sha(fixture['evidence']['prestart.json'])
            with self.subTest(name=name,change=change),ExitStack() as stack:
                digest=self.receipt_context(stack,fixture)
                with self.assertRaises(cut.p.Refused):
                    cut.recovery_receipt(fixture['plan'],fixture['before'],fixture['old'][0],digest)

    def test_duplicate_raw_identity_or_unread_empty_output_refuses(self):
        for wrong in ('raw_duplicate','raw_offset','output_empty_fd'):
            fixture=self.fixture();proof=cut.p.parse(fixture['evidence']['prestart.json'])
            if wrong=='raw_duplicate':proof['raw_current_proofs'][1]=proof['raw_current_proofs'][0]
            elif wrong=='raw_offset':proof['raw_current_proofs'][0]['offset']=11
            else:proof['output_eof_proofs'][0]['fd_count']=0
            fixture['evidence']['prestart.json']=cut.p.canonical(proof)
            fixture['receipt']['evidence_sha256']['prestart.json']=cut.p.sha(fixture['evidence']['prestart.json'])
            with self.subTest(wrong=wrong),ExitStack() as stack:
                digest=self.receipt_context(stack,fixture)
                with self.assertRaises(cut.p.Refused):
                    cut.recovery_receipt(fixture['plan'],fixture['before'],fixture['old'][0],digest)

    def test_upgrade_archives_source_keeps_phase_intent_and_is_idempotent(self):
        fixture=self.fixture();old=fixture['old'];source=b'recovery revision source'
        frozen=copy.deepcopy(old[0]);commits=[]
        with ExitStack() as stack:
            stack.enter_context(patch.object(cut,'RECOVERY_PREVIOUS_LEDGER',cut.p.sha(old[1])))
            fixture['receipt']['previous_ledger_sha256']=cut.p.sha(old[1])
            stack.enter_context(patch.object(cut,'recovery_receipt',return_value=fixture['receipt']))
            stack.enter_context(patch.object(cut,'maintenance_paused'))
            stack.enter_context(patch.object(os.path,'lexists',return_value=False))
            stack.enter_context(patch.object(cut,'require_barrier'))
            stack.enter_context(patch.object(cut,'read_json',side_effect=lambda path,*a:
                ({},b'blocked\n',{}) if Path(path)==cut.BARRIER else
                (cut.p.parse(fixture['evidence'][Path(path).name]),fixture['evidence'][Path(path).name],{})))
            stack.enter_context(patch.object(cut,'unit_status',return_value=fixture['receipt']['vector_after']))
            stack.enter_context(patch.object(cut.p,'proc_identity',return_value={'start_ticks':11223}))
            stack.enter_context(patch.object(cut.p,'container',return_value={'cid':'s','mounts':[],'process':{'pid':20}}))
            stack.enter_context(patch.object(cut.p,'snapshot',side_effect=lambda path,*a,**kw:
                (b'timer\n' if Path(path).name=='capstone-vector-maintenance.timer' else source,
                 {'uid':0,'gid':0,'mode':0o400})))
            protect=stack.enter_context(patch.object(cut,'protected'))
            publish=stack.enter_context(patch.object(cut,'durable_create'))
            commit=stack.enter_context(patch.object(cut,'ledger_commit',side_effect=fake_commit))
            result=cut.accept_v1_recovery(fixture['plan'],fixture['before'],old,'f'*64)
            replay=cut.accept_v1_recovery(fixture['plan'],fixture['before'],result,'f'*64)
            self.assertIs(replay,result);self.assertEqual(commit.call_count,1)
            self.assertEqual(publish.call_count,1)
            self.assertEqual(protect.call_args.args[1]['units']['capstone-vector.service']['InvocationID'],'d'*32)
        self.assertEqual(old[0],frozen)
        self.assertEqual(result[0]['sequence'],7)
        self.assertEqual(result[0]['intent'],frozen['intent'])
        self.assertEqual(result[0]['phase'],frozen['phase'])
        self.assertEqual(result[0]['containers'],frozen['containers'])
        self.assertEqual(result[0]['cutover_sha256'],cut.p.sha(source))

    def test_conflicting_receipt_replay_refuses_without_commit(self):
        fixture=self.fixture();old=fixture['old']
        old[0]['v1_recovery']={'receipt_sha256':'a'*64,'previous_ledger_sha256':cut.RECOVERY_PREVIOUS_LEDGER}
        with patch.object(cut,'recovery_receipt',return_value=fixture['receipt']), \
             patch.object(cut,'ledger_commit') as commit,self.assertRaises(cut.p.Refused):
            cut.accept_v1_recovery(fixture['plan'],fixture['before'],old,'f'*64)
        commit.assert_not_called()


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,
                     'native root filesystem fixtures run only in the operator task directory')
class NativePublicationContracts(unittest.TestCase):
    def setUp(self):
        root=Path(os.environ['CAPSTONE_RAW_TEST_TMP'])
        self.assertTrue(root.is_absolute() and root.is_dir() and not root.is_symlink())
        self.area=tempfile.TemporaryDirectory(prefix='raw-cutover-fixture-',dir=root)
        self.root=Path(self.area.name)
        self.old_umask=os.umask(0o077)
    def tearDown(self):
        os.umask(self.old_umask); self.area.cleanup()
    def test_missing_and_changed_dependency_refuse_before_code_execution(self):
        script=self.root/'cutover-raw-operations-a.py'
        script.write_bytes((HERE/'cutover-raw-operations-a.py').read_bytes())
        dependency=self.root/'deploy-raw-operations-a.py'; marker=self.root/'must-not-exist'
        for present in (False,True):
            if present:
                dependency.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\n')
            result=subprocess.run([sys.executable,'-B',str(script),'inspect','f'*64],capture_output=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads(result.stdout)['reason'],'preparation_dependency_unavailable')
            self.assertFalse(marker.exists())

    def test_create_replay_and_conflict_preserve_original(self):
        target=self.root/'state'
        cut.durable_create(target,b'first\n',0o600)
        inode=target.stat().st_ino
        cut.durable_create(target,b'first\n',0o600)
        self.assertEqual(target.stat().st_ino,inode)
        with self.assertRaises(cut.p.Refused): cut.durable_create(target,b'other\n',0o600)
        self.assertEqual(target.read_bytes(),b'first\n')
    def test_partial_create_prefix_recovers_but_unknown_preserved(self):
        target=self.root/'state'; temp=self.root/'.migration-create-state'
        cut.p.write_new(temp,b'can',0o600)
        cut.durable_create(target,b'candidate\n',0o600)
        self.assertEqual(target.read_bytes(),b'candidate\n')
        target.unlink(); cut.p.write_new(temp,b'foreign',0o600)
        with self.assertRaises(cut.p.Refused): cut.durable_create(target,b'candidate\n',0o600)
        self.assertEqual(temp.read_bytes(),b'foreign'); self.assertFalse(target.exists())
    def test_crash_after_link_publication_recovers_without_duplicate_inode(self):
        target=self.root/'state'; temp=self.root/'.migration-create-state'
        cut.p.write_new(temp,b'candidate\n',0o600); os.link(temp,target)
        inode=target.stat().st_ino
        cut.durable_create(target,b'candidate\n',0o600)
        self.assertEqual((target.stat().st_ino,target.stat().st_nlink),(inode,1))
        self.assertFalse(temp.exists())
    def test_durable_create_sync_failure_then_exact_retry(self):
        target=self.root/'state'
        with patch.object(cut.p,'fsync_dir',side_effect=OSError('fixture')):
            with self.assertRaises(OSError): cut.durable_create(target,b'candidate\n',0o600)
        self.assertEqual(target.read_bytes(),b'candidate\n')
        cut.durable_create(target,b'candidate\n',0o600)
        self.assertEqual(target.stat().st_nlink,1)
    def test_partial_replacement_can_resume_but_unknown_source_refuses(self):
        target=self.root/'config'; temp=self.root/'.capstone-initial-config'
        cut.p.write_new(target,b'old\n',0o600); cut.p.write_new(temp,b'ca',0o600)
        cut.ensure_replacement(target,b'candidate\n',cut.p.sha(b'old\n'),0,0,0o600)
        inode=target.stat().st_ino
        cut.ensure_replacement(target,b'candidate\n',cut.p.sha(b'old\n'),0,0,0o600)
        self.assertEqual(target.stat().st_ino,inode)
        target.write_bytes(b'foreign\n')
        with self.assertRaises(cut.p.Refused):
            cut.ensure_replacement(target,b'candidate\n',cut.p.sha(b'old\n'),0,0,0o600)
        self.assertEqual(target.read_bytes(),b'foreign\n')
    def test_symlink_and_extra_hardlink_refuse(self):
        target=self.root/'state'; actual=self.root/'actual'
        cut.p.write_new(actual,b'candidate\n',0o600); target.symlink_to(actual)
        with self.assertRaises((cut.p.Refused,OSError)): cut.durable_create(target,b'candidate\n',0o600)
        target.unlink(); os.link(actual,target)
        with self.assertRaises(cut.p.Refused): cut.durable_create(target,b'candidate\n',0o600)
        self.assertEqual(actual.read_bytes(),b'candidate\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
