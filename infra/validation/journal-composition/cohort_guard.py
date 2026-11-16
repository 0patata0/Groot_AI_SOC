"""Pure, fail-closed gates for the operator's three-host release.

These decisions alone do not stop/start consumers, grant approval, confirm a
release or cancel recovery timers. The eventual coordinator must supply fresh
authenticated witness replies and independently verify running services/MCP.
"""
from datetime import datetime,timedelta
import hashlib
import importlib.util
from pathlib import Path

SPEC=importlib.util.spec_from_file_location('cohort_source_contract',Path(__file__).with_name('release_status.py'))
contract=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(contract)
need=contract.need
Refused=contract.Refused
MAX_AGE=15
MAX_SPAN=5
POLICY='application-severity-v1'
INTENTS=frozenset({'verify_candidate','confirm_peers','confirm_b','resume_candidate','resume_baseline'})


class Cohort:
    def __init__(self, plan):
        need(isinstance(plan,dict) and set(plan)=={'schema','release_id','hosts'},'cohort_plan_shape')
        need(type(plan['schema']) is int and plan['schema']==1,'cohort_plan_schema')
        need(isinstance(plan['release_id'],str) and contract.RELEASE.fullmatch(plan['release_id']),'cohort_release_id')
        need(isinstance(plan['hosts'],dict) and set(plan['hosts'])==set(contract.TARGETS),'cohort_host_set')
        self.rows={};self.release_id=plan['release_id']
        for host,rows in plan['hosts'].items():
            need(isinstance(rows,list) and len(rows)==len(contract.TARGETS[host]),'cohort_rows')
            by_path={}
            for r in rows:
                need(isinstance(r,dict) and set(r)=={'target','before_sha256','after_sha256','uid','gid','mode'},'cohort_row_shape')
                p=r['target'];need(isinstance(p,str) and p in contract.TARGETS[host] and p not in by_path,'cohort_target')
                before,after=r['before_sha256'],r['after_sha256']
                need((before is None and p in contract.OPTIONAL or isinstance(before,str) and contract.HEX.fullmatch(before))
                     and isinstance(after,str) and contract.HEX.fullmatch(after),'cohort_digest')
                need(all(type(r[k])is int and 0<=r[k]<65534 for k in ('uid','gid'))
                     and type(r['mode'])is int and r['mode']in(0o550,0o600,0o640,0o644,0o755),'cohort_metadata')
                by_path[p]=dict(r)
            need(set(by_path)==contract.TARGETS[host],'cohort_target_set')
            need(any(r['before_sha256']!=r['after_sha256']for r in rows),'cohort_unchanged_host')
            self.rows[host]=by_path
        self.sha256=hashlib.sha256(contract.canonical(plan)).hexdigest()

    def check(self, replies, intent, *, now):
        """Return only allow/hold. A complete proof never authorizes a write."""
        need(isinstance(intent,str) and intent in INTENTS,'cohort_intent')
        need(isinstance(now,datetime) and now.utcoffset()==timedelta(hours=9),'cohort_clock_kst')
        try:self._check(replies,intent,now)
        except (ValueError,KeyError,TypeError,OverflowError):
            return {'allow':False,'intent':intent,'reason':'fresh_coherent_proof_required','contract_sha256':self.sha256}
        return {'allow':True,'intent':intent,'reason':'fresh_coherent_proof','contract_sha256':self.sha256}

    def _check(self,replies,intent,now):
        need(isinstance(replies,dict) and set(replies)==set(self.rows),'cohort_replies')
        baseline=intent=='resume_baseline';times=[]
        for host,value in replies.items():
            need(isinstance(value,dict) and set(value)=={'schema','kind','host','release_id','source_contract_sha256','observed_at_kst','generation','phase','files','cache','mutation_performed','isolated_filesystem'},'cohort_reply_shape')
            need(type(value['schema'])is int and value['schema']==1 and value['kind']=='release_status'
                 and value['host']==host and value['release_id']==self.release_id,'cohort_reply_identity')
            need(value['mutation_performed']is False and value['isolated_filesystem']is False,'cohort_live_read_only')
            need(value['source_contract_sha256']==contract.source_contract(host,self.release_id,list(self.rows[host].values())),'cohort_source_contract')
            need(value['generation']==('baseline'if baseline else 'candidate'),'cohort_generation')
            stamp=datetime.fromisoformat(value['observed_at_kst'])
            need(stamp.utcoffset()==timedelta(hours=9) and -2<=(now-stamp).total_seconds()<=MAX_AGE,'cohort_freshness')
            times.append(stamp)
            files=value['files'];need(isinstance(files,list) and len(files)==len(self.rows[host]),'cohort_files')
            seen=set()
            for f in files:
                need(isinstance(f,dict) and set(f)=={'target','sha256','metadata_matches'},'cohort_file_shape')
                p=f['target'];need(isinstance(p,str) and p in self.rows[host] and p not in seen,'cohort_file_target');seen.add(p)
                need(f['metadata_matches']is True and f['sha256']==self.rows[host][p]['before_sha256'if baseline else 'after_sha256'],'cohort_file_digest')
            need(seen==set(self.rows[host]),'cohort_file_set')
            cache=value['cache'];need(isinstance(cache,dict) and set(cache)=={'status','source_filter_policy'}
                and cache['status']=='observed' and cache['source_filter_policy']==(None if baseline else POLICY),'cohort_cache_policy')
            phase=value['phase']
            if intent=='resume_candidate':need(phase=='confirmed','cohort_confirmed')
            elif baseline:need(phase=='rolled_back','cohort_rolled_back')
            elif intent=='verify_candidate':need(phase=='verified','cohort_verified')
            elif intent=='confirm_b':need(phase in ('verified','confirming')if host=='b'else phase=='confirmed','cohort_peer_commit')
            else:need(phase=='verified'if host=='b'else phase in ('verified','confirming','confirmed'),'cohort_peer_prepare')
        need((max(times)-min(times)).total_seconds()<=MAX_SPAN,'cohort_observation_span')
