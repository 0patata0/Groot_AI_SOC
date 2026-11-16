"""Partition, stale/replayed evidence and partial confirmation stay fenced."""
import copy
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('cohort_guard_tested',Path(__file__).with_name('cohort_guard.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,11,17,2,0,tzinfo=timezone(timedelta(hours=9)));release='a'*32
        self.plan={'schema':1,'release_id':release,'hosts':{}}
        self.proofs={}
        for host,targets in m.contract.TARGETS.items():
            rows=[{'target':p,'before_sha256':None if p in m.contract.OPTIONAL else 'b'*64,'after_sha256':'c'*64,'uid':0,'gid':0,'mode':0o644}for p in sorted(targets)]
            self.plan['hosts'][host]=rows
            self.proofs[host]={'schema':1,'kind':'release_status','host':host,'release_id':release,'observed_at_kst':self.now.isoformat(),
                'source_contract_sha256':m.contract.source_contract(host,release,rows),
                'generation':'candidate','phase':'verified','files':[{'target':r['target'],'sha256':r['after_sha256'],'metadata_matches':True}for r in rows],
                'cache':{'status':'observed','source_filter_policy':m.POLICY},'mutation_performed':False,'isolated_filesystem':False}
        self.gate=m.Cohort(self.plan)

    def check(self,intent='verify_candidate'):
        return self.gate.check(self.proofs,intent,now=self.now)['allow']

    def test_fresh_complete_candidate_is_only_verifiable(self):
        self.assertTrue(self.check());self.assertFalse(self.check('resume_candidate'))

    def test_peers_confirm_first_and_b_last(self):
        self.assertTrue(self.check('confirm_peers'));self.assertFalse(self.check('confirm_b'))
        for h in ('a','c'):self.proofs[h]['phase']='confirmed'
        self.assertTrue(self.check('confirm_b'));self.assertFalse(self.check('resume_candidate'))
        self.proofs['b']['phase']='confirmed';self.assertTrue(self.check('resume_candidate'))

    def test_partial_confirmation_never_resumes(self):
        for phases in (('confirmed','verified','rolled_back'),('rolled_back','rolled_back','confirmed'),('confirmed','confirmed','failed')):
            for h,phase in zip('abc',phases):self.proofs[h]['phase']=phase
            with self.subTest(phases=phases):
                self.assertFalse(self.check('resume_candidate'));self.assertFalse(self.check('resume_baseline'))

    def test_full_restore_requires_old_cache_and_old_source(self):
        for host,value in self.proofs.items():
            value.update(generation='baseline',phase='rolled_back');value['cache']['source_filter_policy']=None
            for row in value['files']:row['sha256']=self.gate.rows[host][row['target']]['before_sha256']
        self.assertTrue(self.check('resume_baseline'))
        self.proofs['c']['cache']['source_filter_policy']=m.POLICY;self.assertFalse(self.check('resume_baseline'))

    def test_partition_or_incomplete_host_set_holds(self):
        del self.proofs['a'];self.assertFalse(self.check())

    def test_stale_or_future_peer_holds(self):
        for seconds in (-16,3):
            self.proofs['a']['observed_at_kst']=(self.now+timedelta(seconds=seconds)).isoformat();self.assertFalse(self.check())

    def test_individually_fresh_but_nonoverlapping_observations_hold(self):
        self.proofs['a']['observed_at_kst']=(self.now-timedelta(seconds=6)).isoformat();self.assertFalse(self.check())

    def test_different_release_id_or_host_holds(self):
        self.proofs['a']['release_id']='d'*32;self.assertFalse(self.check())
        self.proofs['a']['release_id']=self.plan['release_id'];self.proofs['a']['host']='c';self.assertFalse(self.check())

    def test_reported_candidate_label_does_not_replace_each_file_hash(self):
        self.proofs['b']['files'][0]['sha256']='d'*64;self.assertFalse(self.check())

    def test_duplicate_path_cannot_replace_missing_file(self):
        self.proofs['b']['files'][-1]=copy.deepcopy(self.proofs['b']['files'][0]);self.assertFalse(self.check())

    def test_mode_mismatch_holds(self):
        self.proofs['b']['files'][0]['metadata_matches']=False;self.assertFalse(self.check())

    def test_other_config_metadata_cannot_reuse_same_release_identity(self):
        rows=copy.deepcopy(self.plan['hosts']['b']);rows[0]['mode']=0o600
        self.proofs['b']['source_contract_sha256']=m.contract.source_contract('b',self.plan['release_id'],rows)
        self.assertFalse(self.check())

    def test_unavailable_cache_is_never_treated_as_empty(self):
        self.proofs['b']['cache']={'status':'unavailable','source_filter_policy':None};self.assertFalse(self.check())

    def test_matching_sources_with_old_policy_hold(self):
        self.proofs['b']['cache']['source_filter_policy']=None;self.assertFalse(self.check())

    def test_unknown_or_mixed_generation_holds(self):
        for gen in ('baseline','mixed','foreign',None):
            self.proofs['b']['generation']=gen;self.assertFalse(self.check())

    def test_fixture_or_mutating_observation_cannot_confirm_live(self):
        self.proofs['b']['isolated_filesystem']=True;self.assertFalse(self.check())
        self.proofs['b']['isolated_filesystem']=False;self.proofs['b']['mutation_performed']=True;self.assertFalse(self.check())

    def test_utc_unzoned_or_malformed_timestamp_holds(self):
        for stamp in ('2026-11-17T02:00:00+00:00','2026-11-17T02:00:00','not a timestamp',None):
            self.proofs['b']['observed_at_kst']=stamp;self.assertFalse(self.check())

    def test_corrupt_shapes_hold_instead_of_authorizing(self):
        for change in ({'schema':True},{'files':None},{'files':[None]},{'cache':[]},{'phase':None},{'extra':'run'}):
            with self.subTest(change=change):
                old=copy.deepcopy(self.proofs['b']);self.proofs['b'].update(change);self.assertFalse(self.check());self.proofs['b']=old

    def test_intent_cannot_be_arbitrary_command(self):
        with self.assertRaisesRegex(m.Refused,'cohort_intent'):self.check('restart_all')

    def test_plan_scope_digest_and_metadata_are_pinned(self):
        for change in ({'target':'/etc/shadow'},{'mode':0o777},{'uid':True},{'before_sha256':None},{'after_sha256':'x'}):
            with self.subTest(change=change):
                plan=copy.deepcopy(self.plan)
                row=next(r for r in plan['hosts']['a']if r['target']not in m.contract.OPTIONAL)
                row.update(change)
                with self.assertRaises(m.Refused):m.Cohort(plan)

    def test_plan_missing_or_duplicate_host_path_refused(self):
        plan=copy.deepcopy(self.plan);plan['hosts']['a'][-1]=plan['hosts']['a'][0]
        with self.assertRaises(m.Refused):m.Cohort(plan)
        del plan['hosts']['c']
        with self.assertRaises(m.Refused):m.Cohort(plan)


if __name__=='__main__':unittest.main()
