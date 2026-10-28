#!/usr/bin/env python3
"""Validate the exact source or patched tree. Does not install or load anything."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
FILES={'kernel-open/nvidia/nv.c','kernel-open/nvidia/nv-vm.c',
       'src/nvidia/src/kernel/gpu/mem_mgr/mem_desc.c'}


def check(source,patched=False):
    manifest=json.loads((ROOT/'manifest.json').read_text())
    if (manifest.get('schema')!=1 or manifest.get('driver')!='595.78'
            or manifest.get('commit')!='76b260e5967dfe9815b9054a4a4642f10672a763'
            or {f['path'] for f in manifest['files']}!=FILES or len(manifest['files'])!=3):
        raise ValueError('Unexpected source manifest')
    patch=ROOT/'nvidia-595.78-allocation.patch'
    if hashlib.sha256(patch.read_bytes()).hexdigest()!=manifest['patch_sha256']:
        raise ValueError('Diagnostic patch checksum mismatch')
    source=Path(source).resolve(strict=True)
    for entry in manifest['files']:
        path=source/entry['path']
        # Never validate an external target through a directory or file symlink.
        if any(p.is_symlink() for p in [path,*path.parents] if p!=source and source in p.parents):
            raise ValueError('Source symlink is not allowed')
        if not path.is_file() or not path.resolve().is_relative_to(source):
            raise ValueError('Source file missing or outside source root')
        expected=entry['after_sha256' if patched else 'before_sha256']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            raise ValueError('Source checksum mismatch: '+entry['path'])
    return {'status':'matched','driver':manifest['driver'],'commit':manifest['commit'],
            'file_count':3,'tree':'patched' if patched else 'original',
            'installed':False,'loaded':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--expect-patched',action='store_true')
    args=parser.parse_args()
    try:result=check(args.source,args.expect_patched)
    except (OSError,ValueError,KeyError,TypeError) as exc:parser.error(str(exc))
    print(json.dumps(result))


if __name__=='__main__':main()
