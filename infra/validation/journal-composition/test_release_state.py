"""Durable lifecycle journal, lock contention, stale ack and crash recovery intent."""
import copy
from datetime import datetime,timedelta,timezone
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
fixture=load('release_state_file_fixture','test_release_files.py')
m=load('release_state_tested','release_state.py')


class StateJournal(unittest.TestCase):
    setUp=fixture.SourceTransaction.setUp
    prepare=fixture.SourceTransaction.prepare

    def init(self):
        self.fs=self.prepare();self.now=datetime(2026,11,17,3,0,tzinfo=timezone(timedelta(hours=9)))
        self.j=m.Journal(self.fs,'c'*64)
        with self.j.locked():self.j.initialize(self.now+timedelta(minutes=15),now=self.now)
        return self.j

    def mark_arm(self):
        self.j.mark(now=self.now,rollback_ready=True,baseline_sha256='b'*64)
        n=self.j.begin('prepare',now=self.now)
        self.j.finish(n,now=self.now,helpers_prepared=True,barriers_installed=True)

    def through_apply(self):
        j=self.j;self.mark_arm();n=j.begin('arm',now=self.now);j.finish(n,now=self.now,fence_installed=True,barriers_installed=True)
        n=j.begin('quiesce',now=self.now);j.finish(n,now=self.now,services_quiesced=True)
        n=j.begin('backup',now=self.now);j.finish(n,now=self.now,source_backup=True,cache_backup=True)
        n=j.begin('apply',now=self.now);j.finish(n,now=self.now)

    def test_initial_state_is_root_private_and_witness_readable(self):
        j=self.init();value,_=j.read();self.assertEqual(value['phase'],'staged');self.assertEqual(j.path.stat().st_mode&0o777,0o600)
        reply=self.fs.witness.answer({'schema':1,'host':'b','release_id':'a'*32});self.assertEqual(reply['phase'],'staged')

    def test_intent_is_durable_before_work_and_receipt_requires_nonce(self):
        j=self.init()
        with j.locked():
            self.mark_arm();nonce=j.begin('arm',now=self.now);v,_=j.read();self.assertEqual(v['pending']['nonce'],nonce);self.assertEqual(v['phase'],'armed')
            with self.assertRaisesRegex(m.Refused,'operation_nonce'):j.finish('d'*32,now=self.now)
            self.assertEqual(j.read()[0],v)

    def test_ambiguous_action_cannot_be_issued_twice(self):
        j=self.init()
        with j.locked():
            self.mark_arm();j.begin('arm',now=self.now)
        second=m.Journal(self.fs,'c'*64)
        with second.locked():
            with self.assertRaisesRegex(m.Refused,'outcome_requires_inspection'):second.begin('arm',now=self.now)

    def test_rollback_retains_interrupted_intent(self):
        j=self.init()
        with j.locked():
            self.mark_arm();old=j.begin('arm',now=self.now);n=j.begin('rollback',now=self.now)
            v,_=j.read();self.assertEqual(v['phase'],'rolling_back');self.assertEqual(v['interrupted'][0]['nonce'],old)
            j.finish(n,now=self.now,source_restored=True,cache_restored=True,rollback_receipt_sha256='e'*64)
            self.assertEqual(j.read()[0]['phase'],'rolled_back')

    def test_pending_rollback_needs_inspection_not_blind_retry(self):
        j=self.init()
        with j.locked():
            j.begin('rollback',now=self.now)
            with self.assertRaisesRegex(m.Refused,'ambiguous_rollback_requires_inspection'):j.begin('rollback',now=self.now)

    def test_every_write_requires_operation_lock(self):
        j=self.init();value,_=j.read()
        with self.assertRaisesRegex(m.Refused,'operation_lock_required'):j.mark(now=self.now,rollback_ready=True)
        self.assertEqual(j.read()[0],value)

    def test_independent_instance_lock_is_busy(self):
        j=self.init();second=m.Journal(self.fs,'c'*64)
        with j.locked():
            with self.assertRaisesRegex(m.Refused,'operation_busy'):
                with second.locked():self.fail('second actor entered')
        with second.locked():self.assertTrue(second.held)

    def test_nested_lock_does_not_release_outer_lock(self):
        j=self.init()
        with j.locked():
            with self.assertRaisesRegex(m.Refused,'nested_operation_lock'):
                with j.locked():pass
            self.assertTrue(j.held)

    def test_phase_cannot_skip_backup_or_verification(self):
        j=self.init()
        with j.locked():
            for op in ('apply','confirm','resume','cleanup'):
                with self.assertRaises(m.Refused):j.begin(op,now=self.now)
            with self.assertRaisesRegex(m.Refused,'operation_prerequisites'):j.begin('arm',now=self.now)

    def test_full_journal_transition_to_verified_confirmed_resumed(self):
        j=self.init()
        with j.locked():
            self.through_apply();n=j.begin('verify',now=self.now);j.finish(n,now=self.now,verification_sha256='f'*64)
            n=j.begin('confirm',now=self.now);self.assertEqual(j.read()[0]['phase'],'confirming')
            j.finish(n,now=self.now,confirmation_sha256='a'*64);n=j.begin('resume',now=self.now)
            j.finish(n,now=self.now,services_resumed=True,resume_sha256='d'*64)
            value,_=j.read();self.assertEqual(value['phase'],'confirmed');self.assertIsNone(value['pending'])
            with self.assertRaisesRegex(m.Refused,'stable_phase_requires_coordinated_decision'):j.begin('rollback',now=self.now)

    def test_receipt_fields_cannot_be_omitted(self):
        j=self.init()
        with j.locked():
            self.mark_arm();n=j.begin('arm',now=self.now);before,_=j.read()
            with self.assertRaisesRegex(m.Refused,'operation_receipt_required'):j.finish(n,now=self.now)
            self.assertEqual(j.read()[0],before)

    def test_expired_deadline_denies_forward_actions_but_allows_recovery(self):
        j=self.init()
        with j.locked():
            self.mark_arm()
            with self.assertRaisesRegex(m.Refused,'release_deadline_elapsed'):j.begin('arm',now=self.now+timedelta(minutes=16))
            j.begin('rollback',now=self.now+timedelta(hours=1));self.assertEqual(j.read()[0]['phase'],'rolling_back')

    def test_kst_only_and_duration_bounded(self):
        j=self.init()
        with j.locked():
            for now in (self.now.replace(tzinfo=None),self.now.astimezone(timezone.utc)):
                with self.assertRaisesRegex(m.Refused,'clock_kst'):j.mark(now=now,rollback_ready=True)
            for seconds in (0,1801):
                with self.assertRaisesRegex(m.Refused,'release_deadline_bound'):j.initialize(self.now+timedelta(seconds=seconds),now=self.now)

    def test_same_release_with_other_plan_digest_is_refused(self):
        self.init();other=m.Journal(self.fs,'d'*64)
        with self.assertRaisesRegex(m.Refused,'state_identity'):other.read()

    def test_facts_are_monotonic_and_cannot_store_paths_commands_or_secrets(self):
        j=self.init()
        with j.locked():
            self.mark_arm()
            for change in ({'rollback_ready':False},{'baseline_sha256':'d'*64},{'command':'restart'},{'token':'secret'}):
                with self.assertRaises(m.Refused):j.mark(now=self.now,**change)

    def test_cas_rejects_stale_ack(self):
        j=self.init()
        with j.locked():
            value,digest=j.read();j.mark(now=self.now,rollback_ready=True);value['sequence']+=1
            with self.assertRaisesRegex(m.Refused,'state_cas_conflict'):j.save(value,digest)

    def test_save_cannot_extend_deadline_or_rewind_sequence(self):
        j=self.init()
        with j.locked():
            value,digest=j.read()
            with self.assertRaisesRegex(m.Refused,'state_sequence_or_deadline'):j.save(value,digest)
            value['sequence']+=1;value['deadline_kst']=(self.now+timedelta(days=1)).isoformat()
            with self.assertRaisesRegex(m.Refused,'state_sequence_or_deadline'):j.save(value,digest)

    def test_nonregular_state_or_lock_is_never_followed(self):
        j=self.init();original=j.path.read_bytes();j.path.unlink();os.mkfifo(j.path)
        with self.assertRaisesRegex(ValueError,'unsafe_file'):j.read()
        j.path.unlink();j.path.write_bytes(original);j.path.chmod(0o600)
        lock=j.w.storage/'.operation.lock';lock.unlink();lock.symlink_to(j.path)
        with self.assertRaises(OSError):
            with j.locked():self.fail('followed lock symlink')

    def test_failed_atomic_state_replace_keeps_previous_receipt(self):
        j=self.init();before=j.path.read_bytes()
        with j.locked(),patch.object(m.os,'replace',side_effect=OSError('simulated storage error')):
            with self.assertRaises(OSError):j.mark(now=self.now,rollback_ready=True)
        self.assertEqual(j.path.read_bytes(),before);self.assertFalse(list(j.path.parent.glob('.state-*')))

    def test_second_initialization_cannot_overwrite_existing_journal(self):
        j=self.init();before=j.path.read_bytes()
        with j.locked():
            with self.assertRaisesRegex(m.Refused,'state_cas_conflict'):j.initialize(self.now+timedelta(minutes=20),now=self.now)
        self.assertEqual(j.path.read_bytes(),before)

    def confirmed(self):
        j=self.j;self.through_apply();n=j.begin('verify',now=self.now);j.finish(n,now=self.now,verification_sha256='f'*64)
        n=j.begin('confirm',now=self.now);j.finish(n,now=self.now,confirmation_sha256='a'*64)

    def test_confirmed_revert_first_denies_normal_reader_phase(self):
        j=self.init()
        with j.locked():
            self.confirmed();j.begin('revert_fence',now=self.now+timedelta(hours=1))
            self.assertEqual(j.read()[0]['phase'],'rolling_back')
            with self.assertRaisesRegex(m.Refused,'coordinated_revert_proof_required'):j.begin('rollback',now=self.now)

    def test_revert_requires_fencing_receipt_and_global_authorization(self):
        j=self.init()
        with j.locked():
            self.confirmed();n=j.begin('revert_fence',now=self.now)
            j.finish(n,now=self.now,revert_fenced=True,revert_fence_sha256='1'*64)
            with self.assertRaisesRegex(m.Refused,'operation_prerequisites'):j.begin('revert',now=self.now)
            with self.assertRaisesRegex(m.Refused,'coordinated_revert_proof_required'):j.begin('rollback',now=self.now)
            j.mark(now=self.now,revert_authorization_sha256='2'*64);n=j.begin('revert',now=self.now)
            j.finish(n,now=self.now,source_restored=True,cache_restored=True,rollback_receipt_sha256='3'*64)
            self.assertEqual(j.read()[0]['phase'],'rolled_back')

    def test_candidate_and_baseline_resume_keep_separate_immutable_receipts(self):
        j=self.init()
        with j.locked():
            self.confirmed();n=j.begin('resume',now=self.now);j.finish(n,now=self.now,services_resumed=True,resume_sha256='4'*64)
            n=j.begin('revert_fence',now=self.now);j.finish(n,now=self.now,revert_fenced=True,revert_fence_sha256='1'*64)
            j.mark(now=self.now,revert_authorization_sha256='2'*64);n=j.begin('revert',now=self.now)
            j.finish(n,now=self.now,source_restored=True,cache_restored=True,rollback_receipt_sha256='3'*64)
            n=j.begin('resume',now=self.now);j.finish(n,now=self.now,baseline_services_resumed=True,baseline_resume_sha256='5'*64)
            facts=j.read()[0]['facts'];self.assertEqual(facts['resume_sha256'],'4'*64);self.assertEqual(facts['baseline_resume_sha256'],'5'*64)

    def test_mismatched_revert_receipt_nonce_is_refused(self):
        j=self.init()
        with j.locked():
            self.confirmed();j.begin('revert_fence',now=self.now)
            with self.assertRaisesRegex(m.Refused,'operation_nonce'):j.finish('9'*32,now=self.now,revert_fenced=True,revert_fence_sha256='1'*64)


if __name__=='__main__':unittest.main()
