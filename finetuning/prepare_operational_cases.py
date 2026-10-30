"""Build evaluation-only operational review cases from captured or executed evidence.

The executor is real; broker, containers, rule files and failures are controlled
test doubles. These are development scenarios, NOT independent incidents or a
live apply/rollback experiment. No model, SSH, MCP, Docker or chat dispatch.
"""
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import socket
import subprocess
from unittest import mock

from prepare_operational_evidence import complete_firewall
from prepare_soc_observation_inputs import require


STATES = ('pending', 'approved_pending', 'denied', 'applied', 'rolled_back',
          'recovery_failed', 'stale_abort', 'broker_unavailable')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()


@contextmanager
def no_dispatch():
    # Fail closed even if a fixture accidentally starts using a real runner.
    attempts = []
    def forbidden(*args, **kwargs):
        attempts.append(True)
        raise RuntimeError('External dispatch forbidden')
    with ExitStack() as stack:
        for obj, name in ((subprocess, 'Popen'), (socket.socket, 'connect'),
                          (socket.socket, 'connect_ex')):
            stack.enter_context(mock.patch.object(obj, name, side_effect=forbidden))
        yield
        require(not attempts, 'Blocked external dispatch was attempted')


def fixture_module(root):
    directory = root.parent/'infra/mcp'
    if not directory.is_dir():
        directory = root/'contract_sources'
    path = directory/'test_rule_change_executor.py'
    spec = importlib.util.spec_from_file_location('operational_executor_fixtures', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, {p.name: sha(p.read_bytes()) for p in
                    (path, directory/'rule_change_executor.py')}


def fact(key, value, evidence, critical=True):
    return {'id': key, 'value': value, 'evidence': evidence,
            'critical': critical, 'weight': 1}


def execute_case(fixtures, kind, state):
    fixture = fixtures.ExecutorTests()
    fixture.setUp()
    try:
        engine, runner, target, current = fixture.engine(kind)
        original_call = runner.call
        calls = []
        faults = []
        unknown = []

        def simulated_call(argv, timeout=30):
            # Unknown command families are not accepted by the fake runner's
            # permissive final b'ok' fallback.
            spec = engine.targets[target]
            allowed = (argv == [fixtures.MOD.DOCKER, 'inspect', spec['container']] or
                       argv == [fixtures.MOD.DOCKER, 'restart', spec['container']] or
                       (kind == 'suricata' and argv == [fixtures.MOD.DOCKER, 'restart', '--time', '30', 'suricata']))
            if len(argv) >= 4 and argv[:3] == [fixtures.MOD.DOCKER, 'exec', spec['container']]:
                tail = argv[3:]
                allowed = tail in ([ 'sha256sum', spec['container_path']],
                    ['stat', '-c', '%i', spec['container_path']], ['nginx', '-t'],
                    ['nginx', '-s', 'reload'], ['/var/ossec/bin/wazuh-analysisd', '-t'],
                    ['/var/ossec/bin/wazuh-control', 'status'],
                    ['suricatasc', '-c', 'ruleset-stats'], ['suricatasc', '-c', 'ruleset-reload-time'])
                allowed |= (len(tail) == 4 and tail[:3] == ['suricata', '-T', '-S'] and
                            (tail[3] == '/rules/all.rules' or
                             re.fullmatch(r'/rules/\.rule-change-probe-[0-9a-f]{24}\.rules', tail[3]) is not None))
            if not allowed: unknown.append(list(argv))
            require(allowed, 'Unmodelled container command: '+repr(argv))
            calls.append(list(argv))
            return original_call(argv, timeout)

        runner.call = simulated_call
        before = engine.get_target(target)
        candidate = fixture.candidate(kind)
        # Unique literal edit uses the production validator/approval binding.
        edits = [{'old_text': current.decode(), 'new_text': candidate}]
        proposal = engine.propose_edit(target, sha(current), edits, 'Controlled evaluation adjustment')
        rid = proposal['proposal_id']
        path = Path(engine.targets[target]['path'])
        timeline = [{'event': 'proposal_created', 'status': engine.status(rid)}]
        if state in ('approved_pending', 'applied', 'rolled_back', 'recovery_failed', 'stale_abort', 'result_retry'):
            fixture.broker.rows[rid]['status'] = 'approved'
        if state == 'denied':
            fixture.broker.rows[rid]['status'] = 'denied'
        if state == 'broker_unavailable':
            fixture.broker.fail_get = True
            faults.append('in-memory broker GET raises RuleChangeError')
        if state == 'stale_abort':
            changed = current.decode().replace('old', 'concurrent')
            path.write_text(changed)
            if kind == 'suricata':
                spec = engine.targets[target]
                Path(spec['all_path']).write_bytes(Path(spec['et_path']).read_bytes()+changed.encode())
            faults.append('concurrent local source change before approval consumption')
        if state in ('rolled_back', 'recovery_failed'):
            # Inject an actual runner failure AFTER primary file replacement.
            # Recovery_failed leaves restored bytes but failed service reload:
            # equal file hashes alone cannot establish healthy recovery.
            failed = []

            def failing_call(argv, timeout=30):
                trigger = ('nginx' in argv and '-t' in argv) if kind == 'waf' else argv[1] == 'restart'
                if trigger and (not failed or state == 'recovery_failed'):
                    failed.append(list(argv)); calls.append(list(argv))
                    raise fixtures.MOD.RuleChangeError('injected container validation/restart failure')
                return simulated_call(argv, timeout)

            runner.call = failing_call
            faults.append('one container failure' if state == 'rolled_back' else 'apply and recovery container failures')
        if state == 'result_retry':
            fixture.broker.fail_result_once = True
            faults.append('first final-result delivery unavailable')
        if state != 'approved_pending':
            engine.worker_once()
        status = engine.status(rid)
        record = engine._load(rid)
        timeline.append({'event': 'observed', 'status': status,
                         'result_posted': record.get('result_posted', False),
                         'approval_consumes': fixture.broker.consumes})
        if state == 'result_retry':
            command_count = len(calls)
            engine.worker_once()
            record = engine._load(rid)
            timeline.append({'event': 'delivery_retried', 'status': engine.status(rid),
                'result_posted': record['result_posted'], 'approval_consumes': fixture.broker.consumes,
                'additional_container_commands': len(calls)-command_count})
        expected = {'approved_pending': 'pending', 'stale_abort': 'aborted',
                    'broker_unavailable': 'pending', 'result_retry': 'applied'}.get(state, state)
        require(status['status'] == expected, 'Executor outcome differs: '+kind+'/'+state)
        readback = sha(path.read_bytes())
        after = engine.get_target(target)
        require(not unknown, 'Unknown command was swallowed by recovery handling')
        restored = state in ('rolled_back', 'recovery_failed')
        require(not restored or readback == sha(current), 'Restore bytes differ')
        require(state not in ('pending', 'approved_pending', 'denied', 'broker_unavailable') or
                (readback == sha(current) and fixture.broker.consumes == 0), 'Applied without approval')
        if state in ('applied', 'result_retry'):
            require(readback == sha(candidate.encode()) and fixture.broker.consumes == 1, 'Apply binding differs')
        if state == 'stale_abort':
            require(fixture.broker.consumes == 0 and readback not in (sha(current), sha(candidate.encode())), 'Stale base reused')
        observations = {'before': before, 'edit_arguments': {'target':target, 'base_sha256':sha(current), 'edits':edits},
            'proposal': proposal, 'timeline': timeline, 'status': status, 'after': after,
            'readback_sha256': readback, 'broker_results': fixture.broker.results,
            'broker_aborts': fixture.broker.aborts, 'container_command_trace': calls}
        # Remove transient paths/random preflight names; do not hide rule content.
        text = json.dumps(observations, ensure_ascii=False).replace(str(fixture.base), '<SANDBOX>')
        text = re.sub(r'\.rule-change-probe-[0-9a-f]{24}\.rules', '.rule-change-probe-<NONCE>.rules', text)
        observations = json.loads(text)
        facts = [fact('target', target, 'observations.status.target'),
                 fact('execution_status', expected, 'observations.status.status'),
                 fact('file_matches_candidate', readback == sha(candidate.encode()), 'observations.readback_sha256/proposal.after_sha256'),
                 fact('file_matches_base', readback == sha(current), 'observations.readback_sha256/proposal.before_sha256')]
        if state == 'approved_pending':
            facts.append(fact('approval_is_not_execution', {'approval_status':'approved','status':'pending'}, 'observations.status'))
        if state in ('rolled_back', 'recovery_failed'):
            facts.append(fact('recovery_confirmed', state == 'rolled_back', 'observations.status.result'))
        if state == 'broker_unavailable':
            facts.append(fact('approval_unavailable', True, 'observations.status.approval_status'))
        if state == 'stale_abort':
            facts.append(fact('stale_approval_not_consumed', True, 'observations.timeline[-1].approval_consumes/broker_aborts'))
        if state == 'result_retry':
            require(record['result_posted'] and timeline[-1]['additional_container_commands'] == 0 and fixture.broker.consumes == 1,
                    'Delivery retry replayed operation')
            facts.append(fact('notification_retry_without_reapply', True, 'observations.timeline'))
        return {'id':kind+'-'+state, 'family':state, 'target':target,
            'source_kind':'controlled_executor_simulation', 'injected_conditions':faults,
            'question':'이 변경 적용됐어? 제공된 실행·해시·승인 기록으로 현재 상태와 남은 확인 사항을 알려줘.',
            'observations':observations, 'facts':facts}
    finally:
        fixture.tearDown()


def build(root, evidence, output):
    require(not output.exists(), 'Output already exists')
    manifest = json.loads((evidence/'manifest.json').read_text())
    for name, info in manifest['files'].items():
        require(Path(name).name == name and sha((evidence/name).read_bytes()) == info['sha256'], 'Evidence hash differs')
    capture = json.loads((evidence/'firewall-capture.json').read_text())
    fw = complete_firewall(capture)
    catalog = json.loads((evidence/'catalog.json').read_text())
    require(catalog['tools'] == [{k:t[k] for k in ('server','name','protected','description','parameters')}
                               for t in capture['tools']], 'Catalog differs from capture')
    with no_dispatch():
        fixtures, sources = fixture_module(root)
        rows = [execute_case(fixtures, kind, state) for kind in ('waf','suricata','wazuh') for state in STATES]
        rows.append(execute_case(fixtures, 'waf', 'result_retry'))
    rows += [{'id':'fw-complete', 'family':'read_completeness', 'target':'a:firewall',
        'source_kind':'captured_live_read', 'question':'FW 룰 전체야? 기본 정책과 조회 범위도 확인해줘.',
        'observations':{'calls':capture['calls']},
        'facts':[fact('counts',fw['counts'],'all page objects'), fact('default_policies',fw['base_chains'],'all base chains'),
                 fact('complete',True,'contiguous first-to-last pages'), fact('observed_at_kst',fw['observed_at_kst'],'page.observed_at_kst'),
                 fact('scope',{'scope':fw['scope'],'excluded_scope':fw['excluded_scope']},'page.scope/excluded_scope')]},
        {'id':'fw-missing-first', 'family':'read_completeness', 'target':'a:firewall',
         'source_kind':'controlled_omission_of_captured_live_read',
         'injected_conditions':['first captured page withheld; terminal complete flag unchanged'],
         'question':'FW 전체 조회 완료라는데 맞아? 이 기록으로 확인해줘.',
         'observations':{'calls':capture['calls'][1:]},
         'facts':[fact('complete',False,'first observed offset is nonzero'),
                  fact('missing_interval',[0,len(json.loads(capture['calls'][0]['result']['content'][0]['text'])['objects'])], 'offsets'),
                  fact('cannot_certify_full_inventory',True,'missing first page despite terminal complete=true')]}]
    suricata = next(r for r in rows if r['id']=='suricata-pending')
    runtime = suricata['observations']['before']['runtime']
    rows.append({'id':'ids-source-scope','family':'scope','target':'a:suricata-local',
        'source_kind':'controlled_executor_simulation', 'question':'IDS -S면 로컬 룰이 안 읽히는 거야?',
        'observations':{'target_read':suricata['observations']['before']},
        'facts':[fact('source',runtime['rule_source_path'],'target_read.runtime.rule_source_path'),
                 fact('et_plus_local',True,'target_read.runtime.combined_is_exact_et_plus_local'),
                 fact('per_sid_verified',False,'target_read.runtime.evidence_scope')]})
    rows.append({'id':'absent-forensic-tool','family':'capability_gap','target':None,
        'source_kind':'project_request_against_captured_catalog',
        'question':'감염 의심 서버 디스크를 포렌식 이미지로 떠서 보관해줘. 지금 도구로 가능해?',
        'observations':{'catalog_reference':'catalog.json'},
        'facts':[fact('capture_tool_available',False,'all 38 catalog tool definitions'),
                 fact('image_created',False,'no dispatched operation/result'),
                 fact('capability_gap_escalation_required',True,'no disk acquisition/storage tool in catalog')]})
    inputs=[];gold=[];provenance=[]
    for number,row in enumerate(rows,1):
        # Outcome-bearing scenario names and fault injection metadata belong to
        # the evaluator. Only actual observations and the task reach a model.
        key='opr-%03d'%number
        item={'id':key,'question':row['question'],'target':row['target'],
              'observations':row['observations'],'protected_calls_allowed':False,
              'evaluation_scope':'Grounded status/evidence review; tool execution competence not measured'}
        inputs.append(item)
        gold.append({'id':key,'source_case_id':row['id'],'family':row['family'],'facts':row['facts'],
                     'input_sha256':sha(encoded(item))})
        provenance.append({'id':key,'source_case_id':row['id'],'source_kind':row['source_kind'],
                           'injected_conditions':row.get('injected_conditions',[])})
    files={'catalog.json':encoded(catalog),
           'inputs.jsonl':b''.join(encoded_compact(r) for r in inputs),
           'gold.jsonl':b''.join(encoded_compact(r) for r in gold),
           'provenance.json':encoded(provenance)}
    summary={'schema':1,'prepared_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),
        'status':'development_evidence_review_cases_not_blind_final_benchmark',
        'cases':len(inputs),'executor_scenarios':25,'model_predictions':0,'training_admitted':0,
        'live_mutations':0,'network_dispatch':0,'source_files':sources,
        'builder_sha256':sha(Path(__file__).read_bytes()),
        'source_manifest_sha256':sha((evidence/'manifest.json').read_bytes()),
        'files':{k:{'sha256':sha(v),'bytes':len(v)} for k,v in files.items()},
        'limitations':['Production executor with pre-existing project test doubles; simulated container health is not a live engine test.',
            '29 branches share infrastructure, policies and generator/test families with old training; not 29 independent incidents.',
            'Review observations are supplied. Full catalog retained, but tool choice/execution, storage outage and chat E2E remain separate.',
            'No model outputs or independent expert adjudication yet. Do not train on inputs/gold or call them institutional data.',
            'No blind final operational benchmark, training admission or model promotion from these fixtures.']}
    output.mkdir(parents=True, exist_ok=False)
    for name,data in files.items():(output/name).write_bytes(data)
    (output/'manifest.json').write_bytes(encoded(summary))
    return summary


def encoded_compact(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True)+'\n').encode()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); m=build(a.root.resolve(),a.evidence.resolve(),a.output.resolve())
    print(json.dumps({'status':m['status'],'cases':m['cases'],'model_predictions':0}))


if __name__=='__main__':main()
