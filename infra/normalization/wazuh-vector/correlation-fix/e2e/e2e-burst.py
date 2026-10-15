#!/usr/bin/env python3
# One-shot operator diagnostic. No package install, daemon, arbitrary path or input retry.
import ast,collections,datetime,hashlib,json,os,pathlib,re,signal,stat,subprocess,sys,time,xml.etree.ElementTree as ET
ROOT=pathlib.Path('/var/tmp/capstone-correlation-fix-20261014')
HERE=ROOT/'e2e'/'e2e-stage'
BUNDLE=ROOT/'canary'/'canary-candidate'
DOCKER='/usr/local/bin/docker'
ETC=pathlib.Path('/var/lib/docker/volumes/single-node_wazuh_etc/_data')
MIDS={'a':'096e90b6243e438aa8a7b392be754732','b':'1e143067c98a44ffba6eaa925dc038d7'}
phase='preflight'
AGGREGATE_FILTER='include "canary-validation"; . as $root | [$manifest.runs[] as $run | [$root[] | select(.data.capstone_validation.run_id==$run.run_id)] | canary_records($run.run_id;$run.repeat_key;$run.cross_key)[]] | sort_by(.run_id,.rule_id)'

def require(v,code):
    if not v: raise RuntimeError(code)
def now():return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat(timespec='seconds')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(args,*,body=None,seconds=25,limit=16777216,allowed=(0,)):
    p=subprocess.Popen(['/usr/bin/timeout','-k','2',str(seconds)]+list(map(str,args)),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:
        stdout,_=p.communicate(input=body,timeout=seconds+5)
    except subprocess.TimeoutExpired:
        # WNOWAIT preserves a zombie leader as our child while descendants may
        # still hold its output pipes. Do not reap/reuse the PID before killpg.
        owned=False
        if p.returncode is None:
            try:
                os.waitid(os.P_PID,p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                owned=True
            except ChildProcessError:pass
        if owned:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        try:p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            # Never wait without a limit even if an escaped descendant kept a
            # pipe open. Only the confirmed child group is signalled above.
            for stream in (p.stdin,p.stdout,p.stderr):
                if stream is not None:stream.close()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:pass
        raise RuntimeError('bounded_command_timeout')
    require(p.returncode in allowed,'bounded_command_failed')
    require(len(stdout)<=limit,'bounded_command_output')
    return p.returncode,stdout

def metadata(p):
    v=p.lstat();require(stat.S_ISREG(v.st_mode) and v.st_uid==0 and v.st_nlink==1 and stat.S_IMODE(v.st_mode)==0o600,'metadata_file_permissions')
    require(v.st_size<=262144,'metadata_size');return json.loads(p.read_text())
def save(p,obj):
    require(not p.is_symlink(),'metadata_symlink')
    tmp=p.with_name(p.name+'.new');require(not tmp.exists() and not tmp.is_symlink(),'metadata_temp_exists')
    with tmp.open('x') as f:json.dump(obj,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    os.chmod(tmp,0o600);os.replace(tmp,p)
def container(name):
    _,wire=command([DOCKER,'inspect',name],limit=1048576)
    v=json.loads(wire)[0];require(v['State']['Running'],'container_not_running')
    return {'id':v['Id'],'started_at':v['State']['StartedAt'],'init_pid':v['State']['Pid']}
def snapshot(role,pins):
    if role=='a':
        require(set(pins)=={'ossec_conf_sha256','vector_config_sha256','waf_container_id','suricata_container_id'},'a_pin_keys')
        pairs={'ossec_conf_sha256':pathlib.Path('/var/ossec/etc/ossec.conf'),'vector_config_sha256':pathlib.Path('/etc/capstone-vector/vector.toml')}
        names={'waf':'waf_container_id','suricata':'suricata_container_id'}
        for service in ['wazuh-agent.service','capstone-vector.service']:command(['systemctl','is-active','--quiet',service])
    else:
        require(set(pins)=={'manager_id','ossec_conf_sha256','local_rules_sha256','vector_rules_sha256','options_sha256'},'b_pin_keys')
        pairs={'ossec_conf_sha256':ETC/'ossec.conf','local_rules_sha256':ETC/'rules/local_rules.xml','vector_rules_sha256':ETC/'rules/capstone_vector_rules.xml','options_sha256':ETC/'local_internal_options.conf'}
        names={'single-node-wazuh.manager-1':'manager_id'}
    require(all(isinstance(x,str) and re.fullmatch('[0-9a-f]{64}',x) for x in pins.values()),'pin_values')
    hashes={k:digest(p) for k,p in pairs.items()};require(all(hashes[k]==pins[k] for k in hashes),'protected_hash_mismatch')
    containers={n:container(n) for n in names};require(all(containers[n]['id']==pins[k] for n,k in names.items()),'container_pin_mismatch')
    return {'protected_hashes':hashes,'containers':containers}
def b_safety():
    root=ET.fromstring('<root>'+(ETC/'ossec.conf').read_text()+'</root>')
    require(not root.findall('.//active-response') and not root.findall('.//integration'),'response_or_integration_enabled')
    rules=ET.fromstring('<root>'+(ETC/'rules/capstone_vector_rules.xml').read_text()+'</root>')
    for rid in ['100293','100294']:
        rule=rules.find('.//rule[@id="'+rid+'"]');require(rule is not None and rule.attrib['level']=='3','canary_rule_level')
        options=[x.text for x in rule.findall('options')];require('no_email_alert' in options and 'no_full_log' in options,'canary_rule_options')
    bot=pathlib.Path('/opt/socbot/soc_bot.py');tree=ast.parse(bot.read_text());funcs={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)}
    def default(fn,key):
        f=funcs[fn];v=dict(zip([a.arg for a in f.args.args][-len(f.args.defaults):],f.args.defaults))[key]
        require(isinstance(v,ast.Constant) and type(v.value) is int,'soc_default_shape');return v.value
    def minimum(caller,callee):
        values=[]
        for c in ast.walk(funcs[caller]):
            if isinstance(c,ast.Call) and isinstance(c.func,ast.Name) and c.func.id==callee:
                v=next((k.value for k in c.keywords if k.arg=='min_level'),None)
                if v is None:values.append(default(callee,'min_level'))
                else:require(isinstance(v,ast.Constant) and type(v.value) is int,'soc_call_shape');values.append(v.value)
        require(values,'soc_calls_missing');return min(values)
    levels={'report':minimum('build_report','recent_alerts'),'summary':minimum('build_summary','agg_alerts'),'monitor':default('recent_fingerprint','min_level')}
    require(min(levels.values())>=5,'soc_minimum_level')
    # The HTTP handler accepts an explicit level, so its function default alone
    # does not prove the automatic monitor's actual query threshold.
    script=pathlib.Path('/opt/hermes-data/scripts/recent_alerts.sh')
    monitor_text=script.read_text();defaults=re.findall(r'\$\{MIN_LEVEL:-([0-9]+)\}',monitor_text)
    require(len(defaults)==1 and int(defaults[0])>=5,'monitor_script_default')
    override_values=[]
    for text in [monitor_text,pathlib.Path('/opt/hermes-data/.env').read_text()]:
        for raw in re.findall(r'(?m)^\s*(?:export\s+)?MIN_LEVEL=(.*)$',text):
            value=raw.strip().strip('"\'')
            require(value.isdigit() and int(value)>=5,'monitor_file_override')
            override_values.append(int(value))
    _,wire=command([DOCKER,'inspect','hermes'],limit=1048576)
    hermes=json.loads(wire)[0];require(hermes['State']['Running'],'monitor_container_not_running')
    env=dict(value.split('=',1) for value in hermes['Config']['Env'] if '=' in value)
    env_level=env.get('MIN_LEVEL')
    require(env_level is None or (env_level.isdigit() and int(env_level)>=5),'monitor_container_override')
    return {'active_response_blocks':0,'integration_blocks':0,'canary_level':3,
            'soc_minimum_levels':levels,'soc_source_sha256':digest(bot),
            'monitor_script_sha256':digest(script),'monitor_default_min_level':int(defaults[0]),
            'monitor_file_override_levels':override_values,
            'monitor_container_override_level':int(env_level) if env_level is not None else None,
            'monitor_scope':'configured recent_alerts.sh; manual HTTP level queries are not constrained here'}
def segment(path,start,count):
    require(0<=start<=10485760 and 0<=count<=10485760,'segment_bound')
    with path.open('rb') as f:f.seek(start);data=f.read(count)
    require(len(data)==count,'segment_short');return data

def send_a(manifest,pins,before):
    global phase
    phase='a_send_preconditions';out=ROOT/'e2e-a';require(not out.exists(),'a_session_already_started');out.mkdir(mode=0o700)
    path=pathlib.Path('/var/log/capstone-vector/canary/normalized.jsonl');st=path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'canary_metadata')
    size=st.st_size;require(size<=10485760,'canary_size');identity=(st.st_dev,st.st_ino)
    prefix=digest(path);results=[];next_offset=size;started=time.monotonic()
    for number,item in enumerate(manifest['runs'],1):
        phase='a_burst_'+str(number)
        remaining=180-(time.monotonic()-started);require(remaining>5,'a_deadline')
        attempted={'run_id':item['run_id'],'attempt_number':number,'at':now(),'input_retry_allowed':False}
        save(out/'last-attempt.json',attempted)
        _,wire=command(['/bin/bash',BUNDLE/'tests/write-canary-a.sh',item['run_id'],'burst'],seconds=min(25,int(remaining)))
        r=json.loads(wire);require(r['run_id']==item['run_id'] and r['delivery_mode']=='burst' and r['cross_pair_pause_seconds']==0,'writer_mode')
        require(r['synthetic_rows_appended']==13 and r['append_readback_sha_and_rows_verified'] and r['append_start_bytes']==next_offset,'writer_contiguous_readback')
        require(r['append_end_bytes']==r['append_start_bytes']+r['bytes'],'writer_range')
        next_offset=r['append_end_bytes'];results.append(r);save(out/'writer-progress.json',{'completed_runs':results,'input_retry_allowed':False})
    phase='a_source_readback';after=path.lstat();require((after.st_dev,after.st_ino)==identity and after.st_size==next_offset,'canary_post_identity_size')
    require(hashlib.sha256(segment(path,0,size)).hexdigest()==prefix,'existing_prefix_changed')
    appended=segment(path,size,next_offset-size);lines=appended.splitlines();require(len(lines)==260 and appended.endswith(b'\n'),'append_260_rows')
    offset=0
    for item,r in zip(manifest['runs'],results):
        piece=appended[offset:offset+r['bytes']];offset+=r['bytes'];require(hashlib.sha256(piece).hexdigest()==r['payload_sha256'],'run_payload_hash')
        rows=[json.loads(x) for x in piece.splitlines()];require(len(rows)==13 and all(x['capstone_validation']['run_id']==item['run_id'] for x in rows),'run_readback_count')
        require(collections.Counter(x['capstone_validation']['scenario'] for x in rows)=={'canary-repeat':5,'canary-cross':2,'canary-repeat-duplicate':5,'canary-historical':1},'scenario_counts')
    require(snapshot('a',pins)==before,'a_protected_state_changed')
    result={'at':now(),'kind':'agent001_burst_source_append','runs':results,'run_count':20,'appended_rows':260,'appended_bytes':len(appended),'appended_sha256':hashlib.sha256(appended).hexdigest(),'prefix_bytes':size,'prefix_sha256_unchanged':True,'canary_identity_unchanged':True,'protected_state_unchanged':True,'within_each_13_rows_artificial_pause_seconds':0,'natural_inter_run_execution_gaps':True,'analysis_or_indexer_ack':False,'input_retries':0}
    save(out/'result.json',result);return {'status':'source_append_verified','run_count':20,'appended_rows':260,'appended_bytes':len(appended),'prefix_preserved':True,'analysis_ack':False,'result_path':str(out/'result.json')}

def verify_b(manifest,pins,before,expected_safety):
    global phase
    out=ROOT/'e2e-b';require(not out.exists(),'b_verification_already_started');out.mkdir(mode=0o700)
    deadline=time.monotonic()+180;pending={x['run_id']:x for x in manifest['runs']};checks={};attempts=collections.Counter();rounds=0
    while pending and time.monotonic()<deadline-35:
        rounds+=1
        for rid in list(pending):
            phase='b_run_readonly_poll';remaining=deadline-time.monotonic()-35
            if remaining<3:break
            attempts[rid]+=1
            rc,wire=command(['/bin/bash',BUNDLE/'history-replay-b/verify-retained-canary-b.sh',rid],seconds=min(23,int(remaining)),allowed=(0,1,124,137))
            if rc==0:
                data=json.loads(wire);require(data['run_id']==rid and data['manager_retained_tail_matches']==2 and data['indexer_documents']==2 and data['exact_canonical_tuples_match'],'per_run_verification')
                checks[rid]=data;save(out/(rid+'.json'),data);del pending[rid]
        if pending and time.monotonic()<deadline-35:time.sleep(min(2,max(0,deadline-time.monotonic()-35)))
    phase='b_total_query'
    indexer=container('single-node-wazuh.indexer-1');ids=[x['run_id'] for x in manifest['runs']]
    fields=['rule.id','rule.level','agent.id','location','data.capstone_validation','data.capstone_norm.event_id','data.capstone_norm.correlation_dedupe_key','data.capstone_norm.correlation_key','data.capstone_norm.source','data.capstone_norm.sensor','data.capstone_norm.schema_version','data.capstone_norm.pipeline']
    query={'size':100,'timeout':'10s','track_total_hits':True,'_source':fields,'query':{'bool':{'filter':[{'terms':{'data.capstone_validation.run_id':ids}}]}}}
    _,raw_index=command([DOCKER,'exec','-i',indexer['id'],'curl','--disable','--silent','--show-error','--fail','--max-time','15','--max-filesize','1048576','--cacert','/usr/share/wazuh-indexer/config/certs/root-ca.pem','--cert','/usr/share/wazuh-indexer/config/certs/admin.pem','--key','/usr/share/wazuh-indexer/config/certs/admin-key.pem','-H','Content-Type: application/json','-X','POST','--data-binary','@-','https://wazuh.indexer:9200/wazuh-alerts-*/_search?allow_partial_search_results=false'],body=json.dumps(query).encode(),seconds=20,limit=1048576)
    response=json.loads(raw_index);shards=response['_shards'];hits=response['hits'];docs=[x['_source'] for x in hits['hits']]
    require(response['timed_out'] is False and not response.get('terminated_early',False) and shards['total']>0 and shards['failed']==0 and shards['successful']==shards['total'],'total_query_shards')
    require(hits['total']['relation']=='eq' and hits['total']['value']==len(docs)==40,'total_query_exact_40')
    _,raw_manager=command([DOCKER,'exec',pins['manager_id'],'sh','-c','tail -n 10000 /var/ossec/logs/alerts/alerts.json | head -c 16777217'],seconds=12,limit=16777216)
    manager_rows=[json.loads(x) for x in raw_manager.splitlines() if x.strip()]
    manager_rows=[x for x in manager_rows if x.get('data',{}).get('capstone_validation',{}).get('run_id') in ids]
    require(len(manager_rows)==40,'manager_exact_40')
    validator=AGGREGATE_FILTER
    tuples=[]
    for rows in [manager_rows,docs]:
        _,wire=command(['jq','-ce','-L',BUNDLE/'history-replay-b','--argjson','manifest',json.dumps(manifest),validator],body=json.dumps(rows).encode(),seconds=5,limit=262144)
        tuples.append(json.loads(wire))
    require(tuples[0]==tuples[1] and len(tuples[0])==40,'aggregate_canonical_tuples')
    require(all(r['rule']['level']==3 for r in docs),'aggregate_level3')
    negatives=sum(r['data']['capstone_validation'].get('scenario') not in ['canary-repeat','canary-cross'] for r in docs);require(negatives==0,'negative_scenario_alert')
    require(snapshot('b',pins)==before and container('single-node-wazuh.indexer-1')==indexer,'b_protected_state_changed')
    require(b_safety()==expected_safety,'b_monitor_safety_changed')
    require(not pending and len(checks)==20,'per_run_deadline_not_verified')
    result={'at':now(),'kind':'agent001_burst_manager_indexer_verification','run_ids':ids,'run_count':20,'manager_alerts':40,'indexer_documents':40,'expected_rule_counts':{'100293':20,'100294':20},'levels':[3],'negative_scenario_alerts':0,'exact_canonical_tuples_match':True,'indexer_shards':shards,'strict_ca_and_hostname_validation':True,'indexer_timed_out':False,'query_terms_cover_every_run':True,'manager_scope':'current alerts.json last10000/16MiB','rounds':rounds,'attempts_by_run':dict(attempts),'input_retries':0,'verification_elapsed_seconds':round(180-(deadline-time.monotonic()),3),'protected_state_unchanged':True,'raw_or_credentials_exported':False}
    save(out/'result.json',result);return result

def main():
    global phase
    require(len(sys.argv)==2 and sys.argv[1] in ['a-preflight','a-send','b-preflight','b-verify'],'mode')
    role,mode=sys.argv[1].split('-');require(os.getuid()==0 and pathlib.Path('/etc/machine-id').read_text().strip()==MIDS[role],'host_or_user')
    os.umask(0o077)
    for p in [ROOT,HERE,BUNDLE]:
        st=p.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'task_directory')
    command(['/bin/bash','-c','cd "$1" && sha256sum -c source.sha256 >/dev/null','bash',BUNDLE])
    manifest=metadata(HERE/'run-manifest.json');pins=metadata(ROOT/('e2e-pins-'+role+'.json'))
    require(manifest['contract']=='canary-burst-20-v1' and len(manifest['runs'])==20,'manifest_contract')
    ids=[x['run_id'] for x in manifest['runs']];require(len(set(ids))==20 and all(re.fullmatch('[0-9a-f]{32}',x) for x in ids),'manifest_unique_ids')
    for r in manifest['runs']:
        for scenario,key in [('canary-repeat','repeat_key'),('canary-cross','cross_key')]:require(r[key]==hashlib.sha256((r['run_id']+':'+scenario).encode()).hexdigest(),'manifest_key_binding')
    before=snapshot(role,pins);safety=b_safety() if role=='b' else None
    if mode=='preflight':
        result={'at':now(),'role':role,'status':'preflight_passed','run_manifest_sha256':digest(HERE/'run-manifest.json'),'snapshot':before,'safety':safety,'input_written':False}
        save(ROOT/('e2e-preflight-'+role+'.json'),result);return result
    if role=='a':return send_a(manifest,pins,before)
    return verify_b(manifest,pins,before,safety)
def entry():
    try:
        print(json.dumps(main()))
    except Exception as exc:
        code=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
        result={'at':now(),'status':'not_verified','phase':phase,'error_code':code,'input_retry_allowed':False,'raw_or_credentials_exported':False}
        if ROOT.exists():
            try:save(ROOT/('e2e-'+(sys.argv[1] if len(sys.argv)>1 else 'unknown')+'-failure.json'),result)
            except Exception:pass
        print(json.dumps(result));sys.exit(1)

if __name__ == "__main__":
    entry()
