#!/usr/bin/env python3
"""Administrator-only offline build/export; runtime import is bootstrap.py."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

BASE=Path(__file__).resolve().parent
# The approved offline host has the Docker CLI/daemon, without buildx.
# Select the bundled classic builder explicitly; never fetch a builder plugin.
ENV={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LC_ALL':'C','DOCKER_BUILDKIT':'0'}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def trusted_directory(path):
    p=Path(path);need(p.is_absolute() and '..' not in p.parts,'absolute_path_required')
    for q in [p,*p.parents]:
        s=q.lstat();need(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'root_owned_path_required')
    need(p.is_dir(),'directory_required')
    return p


def trusted(path):
    p=Path(path);trusted_directory(p.parent)
    s=p.lstat();need(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'root_owned_path_required')
    s=p.stat();need(p.is_file() and s.st_nlink==1,'regular_single_link_file_required')
    return p


def docker(args,timeout=60,log=None):
    binary=next((str(p) for p in (Path('/usr/local/bin/docker'),Path('/usr/bin/docker')) if p.is_file() and not p.is_symlink()),None)
    need(binary is not None,'docker_required');trusted(binary)
    with (open(log,'xb') if log else tempfile.TemporaryFile()) as output:
        if log:os.fchmod(output.fileno(),0o600)
        p=subprocess.run([binary,'--host','unix:///var/run/docker.sock',*args],env=ENV,stdout=output,stderr=output,timeout=timeout)
        need(p.returncode==0,'docker_operation_failed')
        if log:return b''
        output.seek(0);raw=output.read(4*1024*1024+1);need(len(raw)<=4*1024*1024,'docker_output_limit')
        return raw


def config(image):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image),'fixed_image_id_required')
    rows=json.loads(docker(['image','inspect',image]));need(len(rows)==1 and rows[0]['Id']==image and rows[0]['Os']=='linux' and rows[0]['Architecture']=='amd64','image_identity_changed')
    need(not rows[0]['Config'].get('Volumes'),'anonymous_volumes_forbidden')
    return rows[0]


def build(args):
    trusted_directory(args.output.parent);need(not args.output.exists() and not args.output.is_symlink(),'new_result_required')
    evidence=json.loads(trusted(args.contexts/'provenance.json').read_bytes())
    need(evidence.get('ubuntu_signatures_verified') is True and evidence.get('samba_signature_verified') is True,'signature_preparation_required')
    result={'schema':1,'provenance_sha256':digest(args.contexts/'provenance.json'),'images':{},'attack_tested':False,'service_verified':False}
    for lab in ('redis','samba'):
        context=args.contexts/lab;manifest=trusted(context/'SHA256SUMS').read_text().splitlines();seen=set()
        for line in manifest:
            sha,name=line.split('  ',1);need(re.fullmatch('[0-9a-f]{64}',sha) and re.fullmatch('[A-Za-z0-9_.+~/-]+',name) and '..' not in Path(name).parts,'context_manifest_invalid')
            need(name not in seen,'context_manifest_duplicate');seen.add(name)
            need(digest(trusted(context/name))==sha,'context_changed')
        need({str(p.relative_to(context)) for p in context.rglob('*') if p.is_file()}==seen|{'SHA256SUMS'},'context_untracked_file')
        for item in context.rglob('*'):need(not item.is_symlink(),'context_symlink')
        expected={'redis':'5.0.7','samba':'4.6.3'}[lab]
        with tempfile.TemporaryDirectory(prefix='nonweb-iid-',dir='/root') as work:
            iid=Path(work)/'image.id'
            docker(['build','--pull=false','--network=none','--no-cache','--iidfile',str(iid),str(context)],timeout=3600,log=args.output.parent/(lab+'-build.log'))
            image=iid.read_text().strip();obj=config(image)
        labels=obj['Config'].get('Labels',{})
        need(labels.get('io.capstone.nonweb-lab')==lab and labels.get('io.capstone.software-version')==expected,'built_image_labels')
        result['images'][lab]={'image_id':image,'version':expected,'start_sha256':digest(context/'start.sh'),'verifier_sha256':digest(context/'verify.sh')}
    need(not args.output.exists(),'new_result_required');args.output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');args.output.chmod(0o600)
    return result


def export(args):
    trusted_directory(args.output.parent)
    record=json.loads(trusted(args.result).read_bytes());source=trusted(args.provenance)
    need(record['provenance_sha256']==digest(source),'provenance_changed')
    need(not args.output.exists(),'new_bundle_required');args.output.mkdir(mode=0o700)
    # Preserve the signed-input preparation record as an earlier stage, and
    # distinguish a completed image build from unperformed runtime/attack tests.
    provenance={'schema':1,'preparation':json.loads(source.read_bytes()),'build':record,
                'images_built':True,'service_verified':False,'attack_tested':False}
    (args.output/'provenance.json').write_text(json.dumps(provenance,sort_keys=True,indent=2)+'\n');(args.output/'provenance.json').chmod(0o600)
    manifest={'schema':1,'profile':'capstone-nonweb-v1','images':{},'provenance_sha256':digest(args.output/'provenance.json')}
    for lab in ('redis','samba'):
        row=record['images'][lab];obj=config(row['image_id'])
        # Save by ID, never by a repository tag. The bootstrap validator checks
        # archive RepoTags plus config/OCI manifest/layer relations before load.
        target=args.output/(lab+'-image.tar');docker(['image','save','--output',str(target),row['image_id']],timeout=600);target.chmod(0o600)
        manifest['images'][lab]={**row,'archive':target.name,'archive_sha256':digest(target),
            'archive_size':target.stat().st_size,'software':{'redis':'Redis','samba':'Samba'}[lab]}
    path=args.output/'manifest.json';path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n');path.chmod(0o600)
    # Run the single canonical, read-only import validator before saying the
    # bundle is ready. No runtime creation or image load occurs here.
    helper=trusted(BASE/'bootstrap.py');spec=importlib.util.spec_from_file_location('nonweb_bootstrap',helper)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.read_bundle(args.output)
    return {'status':'offline_bundle_verified','manifest_sha256':digest(path),'bundle':str(args.output),'runtime_started':False,'attack_tested':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    b=sub.add_parser('build');b.add_argument('--contexts',type=Path,required=True);b.add_argument('--output',type=Path,required=True)
    e=sub.add_parser('export')
    for name in ('result','provenance','output'):e.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args()
    try:
        need(os.geteuid()==0 and os.uname().sysname=='Linux','Linux_root_required')
        print(json.dumps(globals()[args.command](args),sort_keys=True))
    except Exception as error:
        print(json.dumps({'status':'refused','reason':str(error) if isinstance(error,ValueError) else type(error).__name__}));return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
