#!/usr/bin/env python3
"""One-shot UID101 WAF v2 producer test. No operating collector or rotator."""
import argparse
import calendar
import datetime
import decimal
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import time
import types
import uuid

ROOT = Path(__file__).resolve().parent
BASE_PATH = ROOT.parent / 'waf-rotation/run-probe-a.py'
BASE_SHA = 'ae12559a4641e596c647bc009a7f0d68906e2890d8201d18fca75537e324f7fe'
BASE_RAW = BASE_PATH.read_bytes()
if hashlib.sha256(BASE_RAW).hexdigest() != BASE_SHA:
    raise SystemExit('frozen_base_sha_mismatch')
base = types.ModuleType('capstone_frozen_waf_rotation')
base.__file__ = str(BASE_PATH)
exec(compile(BASE_RAW, str(BASE_PATH), 'exec'), base.__dict__)
# The helper is a narrowly adapted private fixture; the frozen source is unchanged.
base.ROOT = ROOT
need = base.need
MODE = 'smoke'
V2_RE = re.compile(r'^v2:(?P<binding>[a-f0-9]{64}):(?P<request_id>[a-f0-9]{32}):(?P<msec>[0-9]{10}\.[0-9]{3}):(?P<iso>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2})$')


def write_private(path, raw, *, mode=0o444, uid=0, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        os.fchmod(handle.fileno(), mode)
        os.fchown(handle.fileno(), uid, gid)
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def parsed_v2(value, naive_stamp=None):
    need(isinstance(value, str), 'v2_unique_id_not_string')
    match = V2_RE.fullmatch(value)
    need(match is not None, 'v2_unique_id_format_or_truncation')
    fields = match.groupdict()
    iso = datetime.datetime.fromisoformat(fields['iso'])
    iso_seconds = calendar.timegm(iso.utctimetuple())
    epoch_ms = int(decimal.Decimal(fields['msec']) * 1000)
    # ISO has whole-second precision; msec is the same server clock with ms.
    need(0 <= epoch_ms - iso_seconds * 1000 <= 999, 'v2_iso_epoch_ms_mismatch')
    result = {**fields, 'epoch_ms': epoch_ms, 'unique_id_bytes': len(value.encode()),
              'iso_epoch_difference_ms': epoch_ms - iso_seconds * 1000}
    if naive_stamp is not None:
        need(isinstance(naive_stamp, str), 'audit_naive_stamp_not_string')
        naive = datetime.datetime.strptime(naive_stamp, '%a %b %d %H:%M:%S %Y').replace(tzinfo=iso.tzinfo)
        difference = calendar.timegm(naive.utctimetuple()) * 1000 - epoch_ms
        # transaction context and connector evaluation have second/ms precision.
        need(abs(difference) <= 2000, 'audit_naive_context_time_mismatch')
        result['audit_naive_difference_ms'] = difference
    return result


class V2Probe(base.Probe):
    def __init__(self, output):
        super().__init__(output)
        self.binding = uuid.uuid4().hex + uuid.uuid4().hex
        self.request_windows = {}
        # Root owns every configuration and directory boundary. UID101 gets only
        # fixture log/temp destinations, and cannot replace generation configs.
        os.chmod(self.writer_root, 0o711)
        os.chmod(self.writer_root / 'html', 0o711)
        os.chmod(self.writer_root / 'html/index.html', 0o444)
        for name in ('tmp', 'data', 'upload'):
            os.chown(self.writer_root / name, 101, 101)
            os.chmod(self.writer_root / name, 0o700)
        (self.writer_root / 'run').mkdir(mode=0o700)
        os.chown(self.writer_root / 'run', 101, 101)
        self.stable_format = f'''log_format capstone_private escape=json
 '{{"capstone_waf_access_version":"2-private","deployment_binding":"{self.binding}",'
 '"request_id":"$request_id","time_iso8601":"$time_iso8601","msec":"$msec",'
 '"request_time":"$request_time","source_ip":"$remote_addr","destination_ip":"$server_addr",'
 '"source_port":"$remote_port","destination_port":"$server_port",'
 '"http_method":"$request_method","http_status":"$status"}}';
modsecurity_transaction_id "v2:{self.binding}:$request_id:$msec:$time_iso8601";
'''.encode()
        write_private(self.writer_root / 'stable-format.conf', self.stable_format)
        self.result.update(kind='native_uid101_waf_v2_producer',mode=MODE,
            test_writer_uid=101,test_writer_gid=101,operating_writer_uid_reproduction=True,
            stable_format_sha256=base.sha(self.stable_format),same_binding_across_generations=True,
            raw_reader_test_only=True,production_v2_vrl_executed=False,
            wall_time_contract='server_context_msec_and_ISO_not_access_log_completion_time',
            intended_time_status='trusted_context_creation',time_basis='nginx_modsecurity_context_creation',
            configuration_hash_scope='exact_stable_producer_format_configuration',
            source_sha256={'frozen_base':BASE_SHA,'driver':base.sha(Path(__file__).read_bytes()),
                           'wazuh_helper':base.sha((ROOT/'wazuh-isolated.sh').read_bytes())})
        self.save()

    def nginx_command(self, config=None):
        return ['nsenter','--target',str(self.init),'--mount','--root','--wd=/',
                '--setgid=101','--setuid=101','--','/usr/sbin/nginx','-e',
                self.cprivate+'/run/initial-error.log','-c',config or self.cprivate+'/nginx.conf']

    def refresh_writers(self):
        rows = super().refresh_writers()
        for identity in rows:
            status = Path('/proc',str(identity.pid),'status').read_text()
            for key in ('Uid','Gid'):
                match = re.search(r'^'+key+r':\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$',status,re.M)
                need(match is not None and set(map(int,match.groups()))=={101},'private_writer_uid_gid_not_101')
            groups=re.search(r'^Groups:[ \t]*([^\n]*)$',status,re.M)
            need(groups is not None and set(map(int,groups.group(1).split())).issubset({101}),'private_writer_supplementary_groups')
        return rows

    def write_generation(self, number):
        need(number==len(self.generations)+1 and 1<=number<=2,'generation_not_adjacent')
        directory=self.writer_root/('g'+str(number));directory.mkdir(mode=0o711);os.chmod(directory,0o711)
        cp=self.cprivate+'/g'+str(number)
        paths=f'access_log {cp}/access.json capstone_private;\n'.encode()
        modsec=f'''SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine On
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLogParts ABIJDEFHZ
SecAuditLog {cp}/audit.json
SecAuditLogStorageDir {self.cprivate}/data
SecDebugLog {self.cprivate}/run/modsecurity-debug.log
SecDebugLogLevel 0
SecTmpDir {self.cprivate}/tmp
SecDataDir {self.cprivate}/data
SecUploadDir {self.cprivate}/upload
SecAction "id:9900992,phase:1,pass,log,auditlog,msg:'CAPSTONE_PRIVATE_V2_FIXTURE',severity:5"
'''.encode()
        config=f'''load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
worker_processes 1;
pid {self.cprivate}/run/nginx.pid;
error_log {self.cprivate}/run/nginx-error.log warn;
events {{ worker_connections 64; }}
http {{
 client_body_temp_path {self.cprivate}/tmp;
 proxy_temp_path {self.cprivate}/tmp;
 fastcgi_temp_path {self.cprivate}/tmp;
 uwsgi_temp_path {self.cprivate}/tmp;
 scgi_temp_path {self.cprivate}/tmp;
 client_body_timeout 300s;
 send_timeout 300s;
 keepalive_timeout 1s;
 include {self.cprivate}/stable-format.conf;
 include {cp}/generation-paths.conf;
 modsecurity on;
 modsecurity_rules_file {cp}/modsecurity.conf;
 server {{
  listen 127.0.0.1:{self.port};
  server_name localhost;
  root {self.cprivate}/html;
  add_header X-Capstone-Test-Request-ID $request_id always;
  location / {{ }}
 }}
}}
'''.encode()
        for name,value in [('producer.conf',self.stable_format),('generation-paths.conf',paths),('modsecurity.conf',modsec),('nginx.conf',config)]:
            write_private(directory/name,value)
        for name in ('audit.json','access.json'):
            write_private(directory/name,b'',mode=0o600,uid=101,gid=101)
        row={'generation':number,'binding':self.binding,'config_sha256':base.sha(self.stable_format),
             'directory':directory,'container_directory':cp,'config':config,'expected':[],
             'generation_path_sha256':base.sha(paths),'modsecurity_path_sha256':base.sha(modsec)}
        self.generations.append(row)
        base.run(self.nginx_command(cp+'/nginx.conf')+['-t'],tag='validate_private_v2_'+str(number))
        tmp=self.writer_root/'.next-nginx.conf';write_private(tmp,config)
        os.replace(tmp,self.writer_root/'nginx.conf');base.sync_dir(self.writer_root)
        return row

    def start_writer(self,generation):
        log=(self.writer_root/'stdout.log').open('wb');self.handles.append(log)
        self.master_proc,self.master=self.spawn('nginx_master',self.nginx_command()+['-g','daemon off;'],log,expected_netns=self.netns)
        self.writer_ids[self.master.pid]=self.master
        need(self.master.pid!=self.init,'private_nginx_pid_mismatch')
        self.wait(lambda:base.private_pid_ready(self.writer_root/'run/nginx.pid',self.master.pid),'private_nginx_pid_incomplete',10)
        self.wait(lambda:self.writer_opened(generation),'private_writer_not_opened',10)
        self.private_writes_only();self.current=generation
        self.result['native_writer_uid_gid_verified']=101;self.save()

    def vector_config(self):
        super().vector_config()
        path=self.stage/'vector.toml';text=path.read_text()
        old='id = string!(event.transaction.unique_id)'
        new='''identity = parse_regex!(string!(event.transaction.unique_id), r'^v2:(?P<binding>[a-f0-9]{64}):(?P<request_id>[a-f0-9]{32}):[0-9]{10}\\.[0-9]{3}:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}$')
id = string!(identity.binding) + "-" + string!(identity.request_id)'''
        need(text.count(old)==2,'frozen_vector_template_shape_changed')
        temporary=path.with_suffix('.next');write_private(temporary,text.replace(old,new).encode(),mode=0o600)
        os.replace(temporary,path);base.sync_dir(path.parent)

    def request(self,label,*,pending=False):
        self.request_windows[label]={'start_epoch_ms':time.time_ns()//1000000}
        result=super().request(label,pending=pending)
        if pending:
            self.request_windows[label]['accepted_epoch_ms']=time.time_ns()//1000000
            self.result['request_context_windows']=self.request_windows;self.save()
        return result

    def finish_request(self,sock,label,generation):
        request_id=super().finish_request(sock,label,generation)
        self.request_windows[label].update(end_epoch_ms=time.time_ns()//1000000,request_id=request_id,generation=generation['generation'])
        self.result['request_context_windows']=self.request_windows;self.save()
        return request_id

    def raw_rows(self,generation,kind):
        raw=base.bounded(generation['directory']/(kind+'.json'))
        if not raw:return []
        need(raw.endswith(b'\n'),'partial_synthetic_json_line')
        rows=[]
        for line in raw.splitlines():
            event=json.loads(line)
            if kind=='audit':
                fields=parsed_v2(event['transaction']['unique_id'],event['transaction']['time_stamp'])
                binding=fields['binding'];request_id=fields['request_id']
            else:
                binding=event['deployment_binding'];request_id=event['request_id']
                need(re.fullmatch('[a-f0-9]{32}',request_id) is not None,'access_request_id_invalid')
            need(binding==generation['binding'],'raw_generation_binding_mismatch')
            row={'identity':binding+'-'+request_id,'raw_sha256':base.sha(line)}
            if kind=='audit':
                row.update(wazuh_serialized_sha256=self.wazuh_json.digest(line),v2_time=fields)
            rows.append(row)
        return rows

    def reader_exact(self,generation,*,lane,kind):
        expected=[{'identity':row['identity'],'raw_sha256':row['wazuh_serialized_sha256' if 'wazuh' in lane else 'raw_sha256']} for row in self.raw_rows(generation,kind)]
        ids={generation['binding']+'-'+value for value in generation['expected']}
        actual=[row for row in self.observed(lane) if row['identity'] in ids]
        return len(actual)==len(generation['expected']) and sorted(actual,key=lambda x:x['identity'])==sorted(expected,key=lambda x:x['identity'])

    def preserve(self):
        super().preserve()
        evidence=self.output/'evidence'
        for generation in self.generations:
            directory=evidence/('generation-'+str(generation['generation']))
            write_private(directory/'generation-paths.conf',base.bounded(generation['directory']/'generation-paths.conf'),mode=0o400)
        manifest=json.loads((evidence/'manifest.json').read_bytes())
        manifest.update(schema_version=2,producer_identity_format='v2:binding:request_id:msec:time_iso8601',
                        stable_format_sha256=base.sha(self.stable_format),writer_uid=101,writer_gid=101,
                        time_basis='nginx_modsecurity_context_creation',
                        configuration_hash_scope='exact_stable_producer_format_configuration',
                        raw_reader_verification_only=True,production_v2_vrl_executed=False)
        for row,generation in zip(manifest['generations'],self.generations):
            row.update(generation_path_config=str(evidence/('generation-'+str(row['generation']))/'generation-paths.conf'),
                       generation_path_sha256=generation['generation_path_sha256'],
                       modsecurity_path_sha256=generation['modsecurity_path_sha256'])
        base.atomic(evidence/'manifest.json',manifest);os.chmod(evidence/'manifest.json',0o400);base.sync_dir(evidence)
        self.result['evidence']['manifest_sha256']=base.sha((evidence/'manifest.json').read_bytes());self.save()

    def execute(self):
        self.phase('uid101_first_v2_request')
        g1=self.write_generation(1)
        self.alias('audit',g1);self.alias('access',g1);self.alias('audit',g1,'naive')
        self.start_readers(initial=True);self.start_writer(g1)
        self.request('first_normal');self.wait_generation(g1)
        if MODE=='rotate':
            self.phase('same_binding_new_paths_and_late_old_request')
            self.request('late_old',pending=True)
            g2=self.write_generation(2);self.reload_writer(g2)
            need(self.pending_worker.live() and all(base.count_fd(self.pending_worker,g1['directory']/name,True)>0 for name in ('audit.json','access.json')),'pending_old_worker_proof_lost')
            need(self.raw_counts(g1)==self.pending_counts,'pending_request_logged_before_release')
            self.request('new_generation')
            # Separate context creation from late completion by an observable
            # margin; this is an intentional synthetic hold, not production delay.
            time.sleep(3)
            self.request_windows['late_old']['released_epoch_ms']=time.time_ns()//1000000
            self.pending.sendall(b'B');self.finish_request(self.pending,'late_old',g1);self.pending=None
            self.wait(lambda:self.writer_closed(g1),'old_writer_fds_remain')
            self.wait_generation(g1);self.publish(g2);self.wait_generation(g2)
            need([len(g['expected']) for g in self.generations]==[2,1],'three_request_distribution')
        expected_count=1 if MODE=='smoke' else 3
        self.wait_eof(self.generations[-1])
        times=[]
        for generation in self.generations:
            ids={generation['binding']+'-'+value for value in generation['expected']}
            for kind in ('audit','access'):
                rows=self.raw_rows(generation,kind)
                need(len(rows)==len(ids) and {row['identity'] for row in rows}==ids,'raw_http_identity_set_mismatch')
            for row in self.raw_rows(generation,'audit'):
                fields=row['v2_time'];window=next(x for x in self.request_windows.values() if x.get('request_id')==fields['request_id'])
                need(window['start_epoch_ms']-2000<=fields['epoch_ms']<=window['end_epoch_ms']+2000,'context_timestamp_outside_request_window')
                if 'released_epoch_ms' in window:
                    need(fields['epoch_ms']<=window['accepted_epoch_ms']+1000 and fields['epoch_ms']<=window['released_epoch_ms']-1500,'late_id_uses_completion_not_context_time')
                times.append({key:fields[key] for key in ('epoch_ms','unique_id_bytes','iso_epoch_difference_ms','audit_naive_difference_ms')})
        for lane,kind in [('vector_audit','audit'),('vector_access','access'),('wazuh_audit','audit')]:
            actual=self.observed(lane)
            expected=[{'identity':row['identity'],'raw_sha256':row['wazuh_serialized_sha256' if 'wazuh' in lane else 'raw_sha256']} for generation in self.generations for row in self.raw_rows(generation,kind)]
            need(len(actual)==len(expected)==expected_count and sorted(actual,key=lambda x:x['identity'])==sorted(expected,key=lambda x:x['identity']),'final_reader_exact_'+lane)
        self.stop_writer();need(all(self.writer_closed(g) for g in self.generations),'final_writer_fd_remains')
        self.stop_readers(graceful=True);self.preserve()
        self.result['verification']={'requests':expected_count,'generations':len(self.generations),'writer_uid_gid':101,
            'full_v2_unique_ids_preserved':True,'context_msec_iso_and_audit_time_verified':True,
            'unique_id_lengths':sorted({x['unique_id_bytes'] for x in times}),
            'time_metadata':times,'stable_format_same_in_all_generations':len({g['config_sha256'] for g in self.generations})==1,
            'same_binding':len({g['binding'] for g in self.generations})==1,
            'vector_audit_records':expected_count,'vector_access_records':expected_count,'wazuh_audit_records':expected_count,
            'vector_original_message_sha_equal':True,'wazuh_native_cjson_sha_equal':True,'duplicates':0,
            'late_old_verified':MODE=='rotate','late_old_context_precedes_release':MODE=='rotate',
            'production_v2_vrl_executed':False,'realtime_pair_join_proven':False}
        self.result['operating_after']=base.verify_operating(self.before)
        self.result.update(status='passed',phase='verified');self.save()

    def cleanup(self):
        # Preserve additional UID101 runtime diagnostics on A before the inherited
        # exact-PID cleanup deletes its private tree. Never include raw log text in stdout.
        if self.writer_root is not None and (self.writer_root/'run').exists():
            directory=self.output/'v2-diagnostics';directory.mkdir(mode=0o700,exist_ok=True)
            for name in ('initial-error.log','nginx-error.log','modsecurity-debug.log'):
                path=self.writer_root/'run'/name
                if path.exists():
                    try:write_private(directory/name,base.bounded(path),mode=0o400)
                    except Exception:pass
        super().cleanup()


base.Probe=V2Probe


def main():
    global MODE
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--mode',choices=['smoke','rotate'],default='smoke')
    parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args();MODE=args.mode;output=args.output
    need(os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==base.MID,'wrong_host_or_uid')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    need(re.fullmatch('/var/tmp/capstone-sequential-20261014/step3/producer-v2/run-[A-Za-z0-9_-]{1,48}',str(output)),'output_not_task_scope')
    if args.inside:return base.inner(output)
    need(not output.exists() and not output.is_symlink(),'one_shot_output_already_exists')
    parent=output.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and parent.st_mode&0o077==0,'unsafe_output_parent')
    output.mkdir(mode=0o700);source=output/'source';source.mkdir(mode=0o700)
    for path in (Path(__file__),ROOT/'wazuh-isolated.sh',BASE_PATH):
        write_private(source/path.name,path.read_bytes(),mode=0o400)
    log=(output/'supervisor.log').open('wb')
    def file_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024*1024,16*1024*1024))
    child=subprocess.Popen(['unshare','--net','--',sys.executable,'-B',str(Path(__file__).resolve()),'--inside','--output',str(output),'--mode',MODE],stdout=log,stderr=log,start_new_session=True,preexec_fn=file_limit)
    identity=base.Identity(child.pid)
    try:
        child.wait(timeout=240 if MODE=='smoke' else 480)
    except subprocess.TimeoutExpired:
        if identity.live():identity.send(signal.SIGTERM)
        try:child.wait(timeout=45)
        except subprocess.TimeoutExpired:
            base.emergency_cleanup(output,identity);child.wait(timeout=5)
            raise base.Refused('supervisor_timeout_runtime_files_preserved')
    finally:log.close();identity.close()
    result=json.loads((output/'result.json').read_bytes())
    print(json.dumps({'status':result['status'],'phase':result.get('phase'),'failure_code':result.get('failure_code'),
        'verification':result.get('verification'),'cleanup':result.get('cleanup'),'result_path':str(output/'result.json'),
        'manifest_path':result.get('evidence',{}).get('manifest_path')}))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
