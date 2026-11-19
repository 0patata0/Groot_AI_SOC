#!/usr/bin/env python3
"""Pinned, user-owned Hermes installation and model discovery on Kali.

Entry point: deploy.sh --kali-hermes. This module never runs an attack,
starts a gateway, grants sudo, or changes the inference server.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

COMMIT='ae2a81ccc00e9b7c06301523e5bb09608397149c'
INSTALLER='https://raw.githubusercontent.com/NousResearch/hermes-agent/'+COMMIT+'/scripts/install.sh'
INSTALLER_SHA256='c73dad4dcf7c9ecadb98578e28cc763d23d7be3fa1b513545319038795493214'
RELEASE='v0.23.2'


def digest(path):
    result=hashlib.sha256()
    with path.open('rb')as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):
            result.update(chunk)
    return result.hexdigest()


def extract(archive,destination,regular_only=False):
    """Admit bounded, confined archive members before writing any of them."""
    with tarfile.open(archive)as stream:
        members=stream.getmembers()
        need(len(members)<=100000,'archive_member_bound')
        need(sum(row.size for row in members)<=2147483648,'archive_size_bound')
        seen=set()
        for row in members:
            path=Path(row.name)
            need(not path.is_absolute()and '..'not in path.parts and row.name not in seen,
                 'unsafe_archive_path')
            seen.add(row.name)
            need(row.isfile()or row.isdir()or(not regular_only and row.issym()),'unsafe_archive_type')
            if row.issym():
                need(not Path(row.linkname).is_absolute(),'absolute_archive_link')
                need((destination/path.parent/row.linkname).resolve().is_relative_to(destination.resolve()),
                     'escaping_archive_link')
        stream.extractall(destination,members=members,filter='data')


def offline_environment():
    environment={key:value for key,value in os.environ.items()
                 if not(key.upper().endswith('_PROXY')or key.startswith(('UV_','PIP_','PYTHON')))}
    environment.update(PYTHONDONTWRITEBYTECODE='1',UV_OFFLINE='1',UV_PYTHON_DOWNLOADS='never',
                       PIP_NO_INDEX='1',npm_config_update_notifier='false',npm_config_audit='false')
    return environment


def build_payload(inputs,out,bootstrap_site):
    """Use the pinned upstream PM and assembler; every package source is local."""
    import site
    site.addsitedir(str(bootstrap_site))
    source=inputs/'source'
    os.environ['HERMES_RUNTIME_DIR']=str(out/'tools')
    os.environ['UV_CACHE_DIR']=str(out/'uv-cache')
    sys.path.insert(0,str(source))
    # A missing pre-seeded tool is an error, never a network fallback.
    def audit(event,args):
        if event in ('socket.connect','socket.getaddrinfo'):
            raise RuntimeError('offline_build_network_forbidden')
    sys.addaudithook(audit)
    from pm.build_operations import prepare_tools
    from pm.environment import PythonEnvironment, _fresh_build
    from pm.lock import Facts
    from pm.registry import get_package
    from pm.runtime_stage import stage_runtime
    from scripts.build.agent import assemble
    from scripts.build.inputs import AgentInputs, dependency_site
    from scripts.bundles.payload import seal_pm_runtime
    from scripts.write_install_stamp import build_stamp
    manifest=json.loads((inputs/'inputs.json').read_text())
    store=out/'tools'
    store.mkdir()
    wheelhouse=inputs/'wheelhouse'
    wheelhouse.mkdir()
    names=[]
    for row in manifest['artifacts']:
        artifact=inputs/row['path']
        need(row['kind']in ('wheel','tool')and Path(row['filename']).name==row['filename']
             and re.fullmatch(r'[A-Za-z0-9_.+-]+',row['filename']),'invalid_artifact_name')
        if row['kind']=='wheel':
            os.link(artifact,wheelhouse/row['filename'])
        else:
            names.append(row['package'])
            cached=store/('fetch-'+row['sha256'])
            cached.mkdir()
            os.link(artifact,cached/row['filename'])
    print('Preparing verified offline tools',flush=True)
    prepare_tools(names,out=store,target='linux-x64',cache=out/'uv-cache')
    facts=Facts(store/'facts.json',strict=True)
    python=get_package('python').binary(store/facts.get('python')['entry'],'linux-x64')
    uv=get_package('uv').binary(store/facts.get('uv')['entry'],'linux-x64')
    repo=out/'hermes-agent'
    shutil.copytree(source,repo,symlinks=True)
    os.environ['HERMES_DESKTOP_VARIANT']='bundled'
    os.environ['HERMES_PAYLOAD_TAG']=RELEASE
    stamp=build_stamp(update_mechanism='external',commit=COMMIT,dirty=False,
                      base_version=RELEASE[1:],display_version=RELEASE[1:],distance=0,
                      source='local',distribution='capstone-offline',runtime_dir='..')
    (repo/'install-stamp.json').write_text(json.dumps(stamp,indent=2)+'\n')
    environment=PythonEnvironment(uv=uv,python=python,destination=out/'venv',cache=out/'uv-cache',
                                  env=offline_environment(),offline=True,output=sys.stderr,no_config=True)
    requirements=inputs/'requirements.txt'
    environment.export_requirements(repo,requirements,extras=('all',))
    print('Installing locked Python dependencies from wheelhouse',flush=True)
    with _fresh_build(environment,sealed=True,lock=repo/'uv.lock'):
        environment.install_requirements(requirements.read_text().splitlines(),
                                         wheelhouse=wheelhouse,lock=repo/'uv.lock')
    stage_runtime(uv,python,out/'pm-runtime',project=repo/'pm',offline=True,
                  wheelhouse=wheelhouse,cache=out/'uv-cache')
    seal_pm_runtime(out,python)
    assemble(AgentInputs(project=repo/'pyproject.toml',code=repo,repo='hermes-agent',placement='contained',
                         target='linux-x64',python=python,site_packages=dependency_site(out/'venv','3.14.9','linux-x64'),
                         environment=out/'venv',pm_runtime=out/'pm-runtime',tools=store,ref=COMMIT),out)
    from pm.features import installed_extras,write_features
    from pm.packages import Venv
    features=installed_extras(repo,out/'venv',python_exe=python)
    write_features(features,out)
    facts.record_state('venv',Venv(repo).expected_stamp(features,plugin_dirs=[]),features)
    # Keep the offline cache required by the installed PM; discard input fetch archives.
    for row in manifest['artifacts']:
        cached=store/('fetch-'+row['sha256'])
        if row['kind']=='tool'and cached.is_dir():
            shutil.rmtree(cached)
    (out/'offline-inputs.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Offline payload assembled',flush=True)


def install_offline(bundle,expected,home):
    need(bundle and expected and re.fullmatch('[a-f0-9]{64}',expected),'offline_bundle_and_sha256_required')
    bundle=Path(bundle).resolve()
    need(bundle.is_file()and digest(bundle)==expected,'offline_bundle_digest_mismatch')
    need(platform.machine()=='x86_64','linux_x64_required')
    out=home/'.local/share/capstone-hermes'/RELEASE
    cli=home/'.local/bin/hermes'
    need(out==out.resolve(),'symlinked_install_destination')
    need(not out.exists()and not out.is_symlink()and not cli.exists()and not cli.is_symlink(),
         'existing_install_requires_separate_review')
    out.parent.mkdir(parents=True,exist_ok=True)
    out.mkdir(mode=0o700)
    (out/'capstone-build.json').write_text(json.dumps({'uid':os.getuid(),'source_commit':COMMIT,
                                                     'offline_bundle_sha256':expected})+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='capstone-hermes-build-',dir='/var/tmp')as task:
            inputs=Path(task)
            extract(bundle,inputs,regular_only=True)
            manifest=json.loads((inputs/'inputs.json').read_text())
            need(manifest.get('source_commit')==COMMIT and manifest.get('schema')==1,'offline_source_mismatch')
            rows=manifest['artifacts']+[manifest['source_archive']]
            need(1<=len(rows)<=2048,'offline_manifest_bound')
            expected_paths={'inputs.json'}
            for row in rows:
                path=Path(row['path'])
                need(not path.is_absolute()and '..'not in path.parts,'unsafe_manifest_path')
                file=inputs/path
                need(file.is_file()and not file.is_symlink()and file.stat().st_size==row['bytes']
                     and digest(file)==row['sha256'],'offline_input_digest_mismatch')
                need(row['path']not in expected_paths,'duplicate_manifest_path')
                expected_paths.add(row['path'])
            need({p.relative_to(inputs).as_posix()for p in inputs.rglob('*')if p.is_file()}==expected_paths,
                 'unexpected_bundle_file')
            source=inputs/'source'
            source.mkdir()
            extract(inputs/manifest['source_archive']['path'],source)
            for name,sha in manifest['source_lock_sha256'].items():
                need(name in ('uv.lock','pm/uv.lock','pm/lock.json')and digest(source/name)==sha,
                     'source_lock_digest_mismatch')
            bootstrap=inputs/'bootstrap'
            bootstrap.mkdir()
            tools={row['package']:row for row in manifest['artifacts']if row['kind']=='tool'}
            for name in ('uv','python'):
                extract(inputs/tools[name]['path'],bootstrap/name)
            python=next((bootstrap/'python').rglob('bin/python3.14'))
            uv=next(p for p in(bootstrap/'uv').rglob('uv')if p.is_file())
            sys.path.insert(0,str(source))
            from pm.runtime_stage import stage_runtime
            wheelhouse=inputs/'bootstrap-wheels'
            wheelhouse.mkdir()
            for row in manifest['artifacts']:
                if row['kind']=='wheel':
                    os.link(inputs/row['path'],wheelhouse/row['filename'])
            stage_runtime(uv,python,inputs/'bootstrap-pm',project=source/'pm',offline=True,
                          wheelhouse=wheelhouse,cache=inputs/'bootstrap-cache')
            bootstrap_site=next((inputs/'bootstrap-pm/lib').glob('python*/site-packages'))
            worker='import runpy,sys;sys.argv='+repr([__file__,'--offline-worker',str(inputs),str(out),str(bootstrap_site)])+';runpy.run_path('+repr(str(Path(__file__).resolve()))+',run_name="__main__")'
            subprocess.run([str(python),'-I','-B','-c',worker],env=offline_environment(),check=True,timeout=1800)
            version=checked([str(out/'bin/hermes'),'--version'],timeout=60).decode().strip()
            receipt={'schema':1,'source_commit':COMMIT,'offline_bundle_sha256':expected,'version':version,
                     'installed_at_utc':datetime.now(timezone.utc).isoformat(),'network_acquisition':False}
            (out/'capstone-install.json').write_text(json.dumps(receipt,indent=2)+'\n')
            cli.parent.mkdir(parents=True,exist_ok=True)
            need(not cli.exists()and not cli.is_symlink(),'launcher_created_concurrently')
            cli.symlink_to(out/'bin/hermes')
    except BaseException:
        # Leave the owned failed payload for diagnosis, with no success receipt or launcher.
        (out/'capstone-install.json').unlink(missing_ok=True)
        raise


def need(value,reason):
    if not value:
        raise ValueError(reason)


def endpoint(value):
    url=urllib.parse.urlsplit(value)
    need(url.scheme in ('http','https')and url.hostname and not url.username and not url.password
         and not url.query and not url.fragment and url.path.rstrip('/')in ('','/v1'),'invalid_api_base_url')
    need(url.port is None or 1<=url.port<=65535,'invalid_api_port')
    return urllib.parse.urlunsplit((url.scheme,url.netloc,'/v1','',''))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


def fetch(url):
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with client.open(url,timeout=10)as response:
        raw=response.read(1048577)
        need(response.status==200 and len(raw)<=1048576,'api_response_bound')
        return json.loads(raw)


def models(base):
    body=fetch(base+'/models')
    need(isinstance(body,dict)and isinstance(body.get('data'),list)and len(body['data'])<=256,
         'invalid_model_list')
    names=[]
    for row in body['data']:
        name=row.get('id')if isinstance(row,dict)else None
        need(isinstance(name,str)and 0<len(name)<=256 and '\n'not in name,'invalid_model_id')
        names.append(name)
    need(len(set(names))==len(names),'duplicate_model_id')
    tags={}
    try:
        root=base.rsplit('/v1',1)[0]
        extra=fetch(root+'/api/tags')
        if isinstance(extra,dict)and isinstance(extra.get('models'),list):
            tags={row['name']:row for row in extra['models']if isinstance(row,dict)and isinstance(row.get('name'),str)}
    except (OSError,ValueError,urllib.error.HTTPError):
        pass
    result=[]
    for name in names:
        row=tags.get(name,{})
        details=row.get('details',{})
        result.append({'name':name,'parameter_size':details.get('parameter_size'),
                       'quantization':details.get('quantization_level'),'bytes':row.get('size'),
                       'digest':row.get('digest')})
    return result


def local_user():
    need(platform.system()=='Linux'and os.getuid()==os.geteuid()!=0,'nonroot_linux_user_required')
    need(re.search(r'(?m)^ID=kali\s*$',Path('/etc/os-release').read_text())is not None,'kali_required')
    user=pwd.getpwuid(os.getuid())
    home=Path(user.pw_dir)
    need(home.is_dir()and home.stat().st_uid==os.getuid(),'owned_home_required')
    return user,home


def checked(argv,timeout=30):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,
                     env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
    need(p.returncode==0,'command_failed_'+str(p.returncode))
    need(len(p.stdout)<=1048576 and len(p.stderr)<=65536,'command_output_bound')
    return p.stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--install',action='store_true')
    action.add_argument('--verify',action='store_true')
    action.add_argument('--list-models',action='store_true')
    action.add_argument('--configure',action='store_true')
    action.add_argument('--prepare-bundle',action='store_true')
    action.add_argument('--ensure-model-context',action='store_true')
    parser.add_argument('--api-base-url')
    parser.add_argument('--model')
    parser.add_argument('--offline-bundle',type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--source',type=Path)
    parser.add_argument('--artifacts',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--download',action='store_true')
    parser.add_argument('--context-length',type=int)
    parser.add_argument('--soul-template',type=Path)
    parser.add_argument('--agent-id')
    parser.add_argument('--kali-address')
    parser.add_argument('--source-model')
    parser.add_argument('--source-digest')
    parser.add_argument('--plan',action='store_true')
    args=parser.parse_args()
    base=endpoint(args.api_base_url)if args.api_base_url else None
    need(not(args.list_models or args.configure or args.ensure_model_context)or base,'api_base_url_required')
    need(not args.configure or isinstance(args.model,str)and re.fullmatch(r'[A-Za-z0-9_.:/+-]{1,256}',args.model),
         'model_required')
    need(args.context_length is None or 64000<=args.context_length<=262144,'hermes_context_requires_at_least_64000')
    if args.soul_template:
        need(args.configure and args.agent_id in ('redteam-kali232','redteam-kali233')
             and args.kali_address=='192.168.16.'+args.agent_id[-3:],'invalid_redteam_identity')
    if args.plan:
        print(json.dumps({'release':RELEASE,'commit':COMMIT,'installation':'offline_bundle_required',
                          'api_base_url':base,'model':args.model,'writes':0,'network_requests':0}))
        return
    if args.ensure_model_context:
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from kali_hermes_model import ensure_alias
        print(json.dumps(ensure_alias(base,args.source_model,args.source_digest,args.model,args.context_length)))
        return
    if args.prepare_bundle:
        need(args.source and args.artifacts and args.output,'bundle_source_artifacts_output_required')
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from kali_hermes_bundle import prepare
        print(json.dumps(prepare(args.source,args.artifacts,args.output,args.download)))
        return
    user,home=local_user()
    data=home/'.hermes'
    cli=home/'.local/bin/hermes'
    if args.install or args.configure or args.verify:
        need(not data.is_symlink()and(not data.exists()or data.is_dir()and data.stat().st_uid==os.getuid()),
             'owned_hermes_data_required')
    if args.install:
        install_offline(args.offline_bundle,args.sha256,home)
    if args.install or args.verify or args.configure:
        need(cli.is_file()and os.access(cli,os.X_OK),'hermes_launcher_missing')
        observed=json.loads((home/'.local/share/capstone-hermes'/RELEASE/'capstone-install.json').read_text())
        need(observed.get('source_commit')==COMMIT,'hermes_source_commit_mismatch')
        version=checked([str(cli),'--version']).decode().strip()
    else:
        version=None
    inventory=models(base)if base else []
    if args.configure:
        need(args.model in {row['name']for row in inventory},'model_not_in_live_inventory')
        backup=data/'backups'/('capstone-redteam-'+uuid.uuid4().hex)
        backup.mkdir(parents=True,mode=0o700)
        for name in ('config.yaml','SOUL.md'):
            source=data/name
            need(not source.is_symlink(),'symlinked_user_configuration')
            if source.is_file():
                shutil.copy2(source,backup/name)
                (backup/name).chmod(0o600)
        for key,value in (('model.provider','custom'),('model.base_url',base),('model.default',args.model)):
            checked([str(cli),'config','set',key,value])
        if args.context_length:
            for key in ('model.context_length','model.ollama_num_ctx'):
                checked([str(cli),'config','set',key,str(args.context_length)])
        checked([str(cli),'config','set','security.allow_lazy_installs','false'])
        if args.soul_template:
            text=args.soul_template.read_text()
            need(text.count('{{AGENT_ID}}')==1 and text.count('{{KALI_ADDRESS}}')==1,'invalid_soul_template')
            text=text.replace('{{AGENT_ID}}',args.agent_id).replace('{{KALI_ADDRESS}}',args.kali_address)
            temporary=data/('.SOUL.capstone-'+uuid.uuid4().hex)
            with temporary.open('x')as stream:
                stream.write(text)
            temporary.chmod(0o600)
            os.replace(temporary,data/'SOUL.md')
    result={'at_utc':datetime.now(timezone.utc).isoformat(),'release':'v0.23.2','commit':COMMIT,
            'version':version,'api_base_url':base,'models':inventory,
            'configured_model':args.model if args.configure else None,'inference_requests':0,
            'context_length':args.context_length if args.configure else None,
            'soul_sha256':digest(data/'SOUL.md')if args.configure and args.soul_template else None}
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))


if __name__=='__main__':
    try:
        if len(sys.argv)==5 and sys.argv[1]=='--offline-worker':
            _,home=local_user()
            need(Path(sys.argv[3])==home/'.local/share/capstone-hermes'/RELEASE,'invalid_worker_destination')
            build_payload(*(Path(value)for value in sys.argv[2:]))
        else:
            main()
    except (OSError,ValueError,subprocess.SubprocessError)as error:
        print(json.dumps({'status':'failed','reason':type(error).__name__+':'+str(error)[:160]}))
        raise SystemExit(1)
