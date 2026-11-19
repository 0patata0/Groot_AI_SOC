"""Prepare a hash-locked Linux bundle without installing packages on the sender."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def sha256(path):
    value=hashlib.sha256()
    with path.open('rb')as stream:
        for block in iter(lambda:stream.read(1048576),b''):
            value.update(block)
    return value.hexdigest()


def prepare(source,artifacts,output,download=False):
    lock=Path(__file__).resolve().parents[1]/'infra/hermes/kali-redteam/offline-inputs.json'
    manifest=json.loads(lock.read_text())
    source=source.resolve()
    commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    if commit!=manifest['source_commit']:
        raise ValueError('source_commit_mismatch')
    if subprocess.check_output(['git','-C',str(source),'status','--porcelain','--untracked-files=all']):
        raise ValueError('source_checkout_not_clean')
    for name,expected in manifest['source_lock_sha256'].items():
        if sha256(source/name)!=expected:
            raise ValueError('source_lock_digest_mismatch')
    if output.exists():
        raise FileExistsError('bundle_destination_exists')
    artifacts=artifacts.resolve()
    output=output.absolute()
    output.parent.mkdir(parents=True,exist_ok=True)
    for row in manifest['artifacts']:
        path=artifacts/row['path']
        if not path.exists()and download:
            path.parent.mkdir(parents=True,exist_ok=True)
            temporary=path.with_name(path.name+'.partial')
            if temporary.exists():
                raise FileExistsError('artifact_partial_exists')
            try:
                subprocess.run(['curl','--fail','--location','--silent','--show-error',
                                '--proto','=https','--proto-redir','=https','--tlsv1.2',
                                '--connect-timeout','15','--max-time','600',
                                '--output',str(temporary),row['url']],check=True)
                if temporary.stat().st_size!=row['bytes']or sha256(temporary)!=row['sha256']:
                    raise ValueError('download_digest_mismatch')
                temporary.rename(path)
            finally:
                temporary.unlink(missing_ok=True)
        if not path.is_file()or path.is_symlink()or path.stat().st_size!=row['bytes']or sha256(path)!=row['sha256']:
            raise ValueError('artifact_missing_or_digest_mismatch:'+row['package'])
    with tempfile.TemporaryDirectory(prefix='hermes-offline-package-',dir=output.parent)as task:
        task=Path(task)
        archive=task/'source.tar'
        with archive.open('wb')as stream:
            subprocess.run(['git','-C',str(source),'archive','--format=tar',commit],stdout=stream,check=True)
        expected=manifest['source_archive']
        if archive.stat().st_size!=expected['bytes']or sha256(archive)!=expected['sha256']:
            raise ValueError('source_archive_digest_mismatch')
        inputs=task/'inputs.json'
        inputs.write_text(json.dumps(manifest,indent=2)+'\n')
        temporary=task/'bundle.tar'
        with tarfile.open(temporary,'w')as stream:
            stream.add(inputs,arcname='inputs.json',recursive=False)
            stream.add(archive,arcname='source.tar',recursive=False)
            for row in manifest['artifacts']:
                stream.add(artifacts/row['path'],arcname=row['path'],recursive=False)
        # Exclusive publication preserves a concurrently created destination.
        with output.open('xb')as final,temporary.open('rb')as staged:
            for block in iter(lambda:staged.read(1048576),b''):
                final.write(block)
    return {'bundle_sha256':sha256(output),'bundle_bytes':output.stat().st_size,
            'source_commit':commit,'artifacts':len(manifest['artifacts']),
            'mac_package_installations':0}
