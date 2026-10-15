#!/usr/bin/env python3
"""Terminating, synthetic B-host load trial. No production inputs or edits.

Uses the frozen, previously exercised namespace/chroot helper, not its main().
The driver and native logs stay on B; stdout contains metadata/counts only.
"""
import collections
import copy
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import socket
import stat
import time
import uuid

BASE_SHA = '605f5296dc104c16b528cf6639dbe0a8167bdd5b0d13b8431b4d20f4759f3821'
TASK = Path('/var/tmp/capstone-correlation-fix-20261014')
GROUPS, ROWS_PER_GROUP, EPS, LOAD_SECONDS = 2000, 15, 500, 60
TOTAL = GROUPS * ROWS_PER_GROUP
LOG_BOUND = 120 * 1024 * 1024
LEAVES = ('100293', '100294')


def require(value, code):
    if not value:
        raise RuntimeError(code)


def load_base(path):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == BASE_SHA, 'historical_helper_sha_mismatch')
    spec = importlib.util.spec_from_file_location('frozen_correlation_diagnosis', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True)


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.new')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    os.replace(temporary, path)


def dataset(base, source, run_id, groups=GROUPS):
    """Same canonical bytes in both arms; each group has independent rule state."""
    require(re.fullmatch('[0-9a-f]{32}', run_id) and 0 < groups <= GROUPS, 'dataset_parameters')
    stamp = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()
    events = []
    for group in range(groups):
        group_id = hashlib.sha256(f'{run_id}:{group}'.encode()).hexdigest()[:32]
        rows = base.fixtures(source, group_id, 'fresh', 'forward')
        rows.extend((copy.deepcopy(rows[-1]), copy.deepcopy(rows[-1])))
        for position, row in enumerate(rows):
            validation = row['capstone_validation']
            validation.update(group_number=group, delivery_seq=position+1,
                              load_trial=run_id, load_sequence=len(events)+1)
            norm = row['capstone_norm']
            norm['observed_at_kst'] = stamp
            if norm['correlation_time_class'] == 'fresh':
                norm['event_time_kst'] = stamp
            if position >= 12:
                eid = hashlib.sha256(f'{group_id}:historical:{position}'.encode()).hexdigest()
                norm['event_id'] = norm['correlation_dedupe_key'] = eid
            text = compact(row)
            wire = ('1:[000] '+base.LOCATION+':'+text).encode()+b'\0'
            require(len(wire) < 6000, 'synthetic_datagram_bound')
            events.append({'text':text, 'wire':wire, 'run_id':group_id, 'group':group,
                           'scenario':validation['scenario'], 'position':position+1,
                           'event_id':norm['event_id'], 'sha256':hashlib.sha256(text.encode()).hexdigest()})
    require(len(events) == groups * ROWS_PER_GROUP, 'dataset_count')
    return events


class JsonLines:
    """Incremental bounded reader. No rotation/truncation is allowed in a trial."""
    def __init__(self, path):
        self.path, self.offset, self.pending, self.identity = path, 0, b'', None
        self.rows = 0

    def poll(self):
        if not self.path.exists():
            return []
        st = self.path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink in (1,2), 'trial_log_type')
        identity = (st.st_dev, st.st_ino)
        require(self.identity in (None, identity) and self.offset <= st.st_size <= LOG_BOUND,
                'trial_log_identity_or_bound')
        if self.identity is None and st.st_nlink == 2:
            # Native Wazuh links the current file to its private dated archive.
            # Both names must be regular files inside this trial's log directory.
            links = [p for p in self.path.parent.rglob('*.json') if not p.is_symlink()
                     and p.is_file() and (p.stat().st_dev,p.stat().st_ino)==identity]
            require(len(links)==2 and all(p.resolve().is_relative_to(self.path.parent.resolve()) for p in links),
                    'native_log_hardlink_not_private')
        self.identity = identity
        with self.path.open('rb') as handle:
            handle.seek(self.offset)
            chunk = handle.read(512*1024)
        self.offset += len(chunk)
        lines = (self.pending + chunk).split(b'\n')
        self.pending = lines.pop()
        require(len(self.pending) < 64*1024, 'trial_log_line_bound')
        result = []
        for line in lines:
            require(line and len(line) < 64*1024, 'trial_log_line_invalid')
            value = json.loads(line)
            require(isinstance(value, dict), 'trial_log_object_required')
            result.append(value)
        self.rows += len(result)
        return result

    def at_eof(self):
        return not self.pending and (not self.path.exists() or self.path.stat().st_size == self.offset)


def native_state(path):
    """Only numeric metadata. Comments and text values never leave the host."""
    try:
        st = path.stat()
        require(st.st_size <= 64*1024, 'state_size_bound')
        raw = path.read_text()
    except FileNotFoundError:
        return None
    fields = {}
    for line in raw.splitlines():
        if not line or line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = (piece.strip().strip("'\"") for piece in line.split('=', 1))
        if re.fullmatch('[a-z][a-z0-9_]*', key) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value):
            fields[key] = float(value) if '.' in value else int(value)
    return {'mtime_ns':st.st_mtime_ns, 'values':fields}


def host_capacity():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        parts = line.split()
        if parts[0] in ('MemAvailable:', 'SwapFree:'):
            values[parts[0].rstrip(':')] = int(parts[1])
    values['disk_free_bytes'] = os.statvfs(TASK).f_bavail * os.statvfs(TASK).f_frsize
    values['cpu_affinity_count'] = len(os.sched_getaffinity(0))
    return values


def process_sample(pid):
    values = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS','VmSize','Threads'):
            values[key] = int(value.split()[0])
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
    values['cpu_ticks'] = int(fields[11]) + int(fields[12])
    return values


def quantiles(values):
    if not values:
        return None
    ordered = sorted(values)
    return {key:round(ordered[min(len(ordered)-1, math.ceil(len(ordered)*fraction)-1)],3)
            for key,fraction in (('p50',.5),('p95',.95),('p99',.99),('max',1))}


def state_summary(samples):
    states = [sample['native_state'] for sample in samples if sample['native_state']]
    if not states:
        return {'available':False,'first_counters':{},'final_counters':{},'final_queue_usage':{}}
    first, last = states[0]['values'], states[-1]['values']
    counters = ('events_received','total_events_decoded','events_processed','events_dropped',
                'alerts_written','archives_written')
    queues = sorted({key for sample in states for key in sample['values'] if key.endswith('_queue_usage')})
    return {'available':True,'first_counters':{key:first[key] for key in counters if key in first},
            'final_counters':{key:last[key] for key in counters if key in last},
            'counter_delta':{key:last[key]-first[key] for key in counters if key in first and key in last},
            'max_sampled_queue_usage':{key:max(s['values'].get(key,0) for s in states) for key in queues},
            'final_queue_usage':{key:last.get(key) for key in queues},
            'unique_state_updates':len({s['mtime_ns'] for s in states}),
            'last_state_age_seconds':round((time.time_ns()-states[-1]['mtime_ns'])/1e9,3),
            'poll_seconds':1,'configured_state_interval_seconds':5,
            'sampled_zero_queues_is_continuous_zero_guarantee':False,
            'archive_payload_and_alert_identity_is_primary_drain_evidence':True}


class Observer:
    def __init__(self, base, prefix, events):
        self.base, self.events = base, events
        self.archives = JsonLines(prefix/'logs/archives/archives.json')
        self.alerts = JsonLines(prefix/'logs/alerts/alerts.json')
        self.seen, self.alert_seen = set(), set()
        self.archive_leaves, self.alert_leaves = collections.Counter(), collections.Counter()
        self.group_leaves = collections.Counter()
        self.sent_ns, self.latency_ms = {}, []
        self.last_archive_ns = None

    def identity(self, row):
        value = row.get('data',{}).get('capstone_validation',{})
        seq = value.get('load_sequence')
        require(type(seq) in (int,str) and str(seq).isdigit(), 'output_sequence_invalid')
        seq = int(seq)
        require(1 <= seq <= len(self.events), 'output_sequence_out_of_range')
        expected = self.events[seq-1]
        require(value.get('run_id') == expected['run_id'] and value.get('scenario') == expected['scenario'],
                'output_group_identity')
        require(row.get('agent',{}).get('id') == '000' and row.get('location') in
                (self.base.LOCATION, self.base.LOCATION.split('->',1)[1]), 'output_agent_location')
        require(row['data']['capstone_norm']['event_id'] == expected['event_id'], 'output_event_identity')
        return seq, expected

    def poll(self):
        now = time.monotonic_ns()
        for row in self.archives.poll():
            seq, expected = self.identity(row)
            require(seq not in self.seen and seq in self.sent_ns, 'archive_duplicate_or_unsent')
            require(row.get('full_log') == expected['text'], 'archive_exact_payload_mismatch')
            self.seen.add(seq)
            self.latency_ms.append((now-self.sent_ns[seq])/1e6)
            self.last_archive_ns = now
            rule = str(row.get('rule',{}).get('id',''))
            if rule in LEAVES:
                required_scenario = 'canary-repeat' if rule == '100293' else 'canary-cross'
                require(expected['scenario'] == required_scenario, 'leaf_wrong_scenario')
                self.archive_leaves[(seq,rule)] += 1
                self.group_leaves[(expected['group'],rule)] += 1
            else:
                require(rule in ('100291','100292',''), 'unexpected_archive_rule')
        for row in self.alerts.poll():
            seq, _ = self.identity(row)
            rule = str(row.get('rule',{}).get('id',''))
            require(rule in LEAVES and (seq,rule) not in self.alert_seen, 'unexpected_or_duplicate_alert')
            self.alert_seen.add((seq,rule))
            self.alert_leaves[(seq,rule)] += 1

    def drained(self):
        return len(self.seen) == len(self.events) and self.archive_leaves == self.alert_leaves and self.archives.at_eof() and self.alerts.at_eof()

    def summary(self, groups):
        issues = [{'group':group, 'rule_id':rule, 'actual':self.group_leaves[(group,rule)], 'expected':1}
                  for group in range(groups) for rule in LEAVES if self.group_leaves[(group,rule)] != 1]
        counts = lambda data:dict(collections.Counter(rule for (_,rule),count in data.items() for _ in range(count)))
        return {'sent_rows':len(self.sent_ns), 'archive_rows':len(self.seen),
                'archive_exact_payloads':len(self.seen)==len(self.events),
                'archive_leaf_counts':counts(self.archive_leaves), 'alert_leaf_counts':counts(self.alert_leaves),
                'expected_leaf_counts':{rule:groups for rule in LEAVES}, 'group_leaf_mismatches':issues,
                'exact_group_expectations':not issues, 'alert_writer_drained':self.drained(),
                'send_to_archive_observation_ms':quantiles(self.latency_ms),
                'latency_includes_writer_flush_and_poll':True, 'socket_send_is_analysis_ack':False}


def explicit_threads(prefix, base, profile):
    path = prefix/'etc/local_internal_options.conf'
    overrides = {'analysisd.event_threads':'1' if profile=='single' else '0',
                 'analysisd.rule_matching_threads':'1' if profile=='single' else '0'}
    lines = [line for line in path.read_text().splitlines() if line.strip().split('=',1)[0] not in overrides]
    path.write_text('\n'.join(lines)+'\n'+'\n'.join(key+'='+value for key,value in overrides.items())+'\n')
    return {'local_options_sha256':base.digest(path), 'thread_options':overrides}


def run_arm(base, prefix, arm, events, process, runtime, update):
    observer = Observer(base,prefix,events)
    samples, errors = [], []
    start = time.monotonic()
    start_ns = time.monotonic_ns()
    next_sample, next_progress = start, start+10
    state_path = prefix/'var/run/wazuh-analysisd.state'
    first_proc = process_sample(process.pid)
    def poll():
        nonlocal next_sample,next_progress
        require(process.poll() is None, 'native_process_exited')
        require(base.proc_start(process.pid)==runtime['start_ticks'], 'native_process_identity_changed')
        observer.poll()
        now = time.monotonic()
        if now >= next_sample:
            cap = host_capacity()
            require(cap['MemAvailable'] >= 2*1024*1024 and cap['disk_free_bytes'] >= 512*1024*1024,
                    'host_resource_floor')
            samples.append({'seconds':round(now-start,3), 'native_state':native_state(state_path),
                            'process':process_sample(process.pid), 'capacity':cap,
                            'sent_rows':len(observer.sent_ns), 'archive_rows':len(observer.seen)})
            next_sample = now+1
        if now >= next_progress:
            summary = observer.summary(GROUPS)
            update({'phase':'load_or_drain','elapsed_seconds':round(now-start,3),
                    'sent_rows':summary['sent_rows'],'archive_rows':summary['archive_rows'],
                    'archive_leaf_counts':summary['archive_leaf_counts']})
            next_progress = now+10
    max_lag = 0
    sent_finished = None
    stable_since = None
    stable_seconds = 0
    try:
        poll()
        with (arm/'send-receipts.jsonl').open('w') as receipts, socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.connect(str(prefix/'queue/sockets/queue'))
            for group in range(GROUPS):
                target = start + group*ROWS_PER_GROUP/EPS
                while time.monotonic() < target:
                    poll()
                    time.sleep(min(.005, max(0,target-time.monotonic())))
                lag = time.monotonic()-target
                max_lag = max(max_lag,lag)
                require(lag <= .25, 'sender_schedule_lag_exceeded')
                for index in range(group*ROWS_PER_GROUP,(group+1)*ROWS_PER_GROUP):
                    wire = events[index]['wire']
                    require(sock.send(wire)==len(wire), 'datagram_send_incomplete')
                    sent = time.monotonic_ns()
                    observer.sent_ns[index+1] = sent
                    receipts.write(compact({'sequence':index+1,'sent_monotonic_ns':sent,
                                            'wire_sha256':hashlib.sha256(wire).hexdigest()})+'\n')
                poll()
            sent_finished = time.monotonic()
            while time.monotonic() < start+LOAD_SECONDS:
                poll()
                time.sleep(.01)
        # At least two native state periods, not just the first apparent file EOF.
        drain_started = time.monotonic()
        while time.monotonic() < drain_started+30:
            poll()
            if observer.drained():
                stable_since = stable_since or time.monotonic()
                if time.monotonic()-stable_since >= 10:
                    break
            else:
                stable_since = None
            time.sleep(.02)
        stable_seconds = time.monotonic()-stable_since if stable_since else 0
        require(observer.drained() and stable_seconds >= 10, 'exact_archive_or_alert_stable_drain_timeout')
    except Exception as exc:
        errors.append(str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__)
    summary = observer.summary(GROUPS)
    state_result = state_summary(samples)
    final_state = state_result['final_counters']
    state_result['received_decoded_exact_input_and_zero_drop'] = (
        final_state.get('events_received')==len(events) and final_state.get('total_events_decoded')==len(events)
        and final_state.get('events_dropped')==0)
    state_result['processed_equals_input'] = final_state.get('events_processed')==len(events)
    state_result['final_sampled_queues_zero'] = bool(state_result['final_queue_usage']) and all(
        value==0 for value in state_result['final_queue_usage'].values())
    if not (state_result['available'] and state_result['received_decoded_exact_input_and_zero_drop']
            and state_result['processed_equals_input'] and state_result['final_sampled_queues_zero']
            and 0 <= state_result['last_state_age_seconds'] <= 8):
        errors.append('native_state_final_drain_not_verified')
    summary.update({'samples':samples, 'errors':errors, 'input_rows':TOTAL, 'groups':GROUPS,
                    'scheduled_eps':EPS, 'scheduled_load_seconds':LOAD_SECONDS,
                    'microburst_rows':ROWS_PER_GROUP, 'microburst_period_ms':30,
                    'sent_elapsed_seconds':round(sent_finished-start,6) if sent_finished else None,
                    'actual_sent_eps':round(len(observer.sent_ns)/(sent_finished-start),6) if sent_finished else None,
                    'window_average_sent_eps':round(len(observer.sent_ns)/LOAD_SECONDS,6),
                    'sender_max_schedule_lag_ms':round(max_lag*1000,3),
                    'total_elapsed_seconds':round(time.monotonic()-start,3),
                    'fully_drained_stable_seconds':round(stable_seconds,3),
                    'archive_completion_after_start_seconds':round((observer.last_archive_ns-start_ns)/1e9,6) if observer.last_archive_ns else None,
                    'process_cpu_seconds':round((process_sample(process.pid)['cpu_ticks']-first_proc['cpu_ticks'])/os.sysconf('SC_CLK_TCK'),3) if process.poll() is None else None,
                    'native_state_summary':state_result,
                    'logtest_executed':False, 'raw_archives_remain_on_server':True})
    save(arm/'load-result.json',summary)
    return summary


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    source = Path(__file__).resolve().parent
    base_path = source.parent/'correlation-diagnosis/run-isolated-b.py'
    base = load_base(base_path)
    require(os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==base.MACHINE,'wrong_host_or_user')
    base.protected_dir(TASK)
    capacity = host_capacity()
    require(capacity['cpu_affinity_count']==4 and capacity['MemAvailable']>=4*1024*1024
            and capacity['disk_free_bytes']>=2*1024**3,'initial_capacity_insufficient')
    original, before = base.production()
    trial = TASK/('load-'+uuid.uuid4().hex[:12])
    base.protected_dir(trial,create=True)
    source_bytes = Path(__file__).read_bytes()
    (trial/'runner-source.py').write_bytes(source_bytes)
    (trial/'historical-helper-source.py').write_bytes(base_path.read_bytes())
    events = dataset(base,source.parent/'fixtures/correlation',uuid.uuid4().hex)
    with (trial/'synthetic-input.jsonl').open('w') as handle:
        for event in events:
            handle.write(event['text']+'\n')
    result = {'kind':'private_native_correlation_load_trial','arms':[], 'production_before':before,
              'capacity_before':capacity,'input_rows_per_arm':TOTAL,'same_input_bytes_both_arms':True,
              'source_sha256':hashlib.sha256(source_bytes).hexdigest(),'historical_helper_sha256':BASE_SHA,
              'input_sha256':base.digest(trial/'synthetic-input.jsonl'),
              'agent_id':'000','agent001_transport_equivalence':False,'private_wdb_started':False,
              'operational_inputs_written':False,'native_children_cleaned':True,'trial_directory':str(trial)}
    error = None
    try:
        for profile in ('single','auto'):
            arm = trial/profile
            base.protected_dir(arm,create=True)
            prefix = arm/'root'
            metadata = base.prepare(prefix,original,profile)
            metadata.update(explicit_threads(prefix,base,profile))
            item = {'profile':profile,'hashes':metadata}
            result['arms'].append(item)
            p = None
            try:
                result['native_children_cleaned']=False
                p,start = base.launch(prefix,arm)
                runtime = base.wait_ready(p,prefix,before['analysisd_pid'])
                item['runtime'] = runtime
                def update(progress):
                    item['progress']=progress
                    save(trial/'partial-result.json',result)
                    print(compact({'kind':'load_progress','profile':profile,**progress}),flush=True)
                update({'phase':'ready'})
                item['load'] = run_arm(base,prefix,arm,events,p,runtime,update)
                require(not item['load']['errors'],'load_execution_failed')
            finally:
                if p is not None:
                    base.stop(p,start)
                result['native_children_cleaned']=True
                save(trial/'partial-result.json',result)
            print(compact({'kind':'load_arm_complete','profile':profile,'archive_rows':item['load']['archive_rows'],
                           'leaf_counts':item['load']['archive_leaf_counts'],'exact_group_expectations':item['load']['exact_group_expectations']}),flush=True)
    except Exception as exc:
        error = str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
        result['error']=error
        result['private_diagnostics']={str(p.relative_to(trial)):p.read_text(errors='replace').splitlines()[-20:]
             for pattern in ('*/native-stderr.log','*/root/logs/ossec.log') for p in trial.glob(pattern)}
    finally:
        _, after = base.production()
        result['production_unchanged']=before==after
        result['checked_at_kst']=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()
        result['result_path']=str(trial/'result.json')
        save(trial/'result.json',result)
        print(compact(result),flush=True)
    require(before==after,'production_identity_changed')
    require(not error,'load_trial_failed')


if __name__ == '__main__':
    main()
