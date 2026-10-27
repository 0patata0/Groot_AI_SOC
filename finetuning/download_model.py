"""Download a pinned public base directly on Thor and verify every artifact."""
import fnmatch
import hashlib
import json
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo


def verify_artifact(destination, item):
    relative = Path(item['path'])
    if relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Unsafe artifact path')
    path = Path(destination) / relative
    if path.is_symlink() or not path.resolve().is_relative_to(Path(destination).resolve()):
        raise ValueError('Unsafe artifact link')
    if path.stat().st_size != item['bytes']:
        raise ValueError('Artifact size mismatch: '+item['path'])
    digest = hashlib.sha256() if item['sha256'] else hashlib.sha1()
    if not item['sha256']:
        digest.update(f'blob {item["bytes"]}\0'.encode())
    with path.open('rb') as handle:
        for chunk in iter(lambda:handle.read(8*1024*1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != (item['sha256'] or item['git_blob']):
        raise ValueError('Artifact checksum mismatch: '+item['path'])


def download(config, destination):
    from huggingface_hub import HfApi, snapshot_download
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    info = HfApi(token=False).model_info(config['model_name_or_path'],
        revision=config['revision'], files_metadata=True)
    if info.sha != config['revision']:
        raise ValueError('Resolved base revision does not match the pinned commit')
    patterns = ('*.json', '*.jinja', '*.safetensors', '*.txt', '*.model', 'LICENSE*', 'README.md')
    files = []
    for item in info.siblings:
        if not any(fnmatch.fnmatch(item.rfilename, p) for p in patterns):
            continue
        path = Path(item.rfilename)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('Unsafe repository artifact path')
        files.append({'path': item.rfilename, 'bytes': item.size,
                      'sha256': item.lfs.sha256 if item.lfs else None, 'git_blob': item.blob_id})
    if not any(f['path'].endswith('.safetensors') for f in files):
        raise ValueError('No safetensors weights in pinned repository')
    manifest = {'model':config['model_name_or_path'], 'revision':info.sha,
                'files':files, 'verified':False,
                'started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat()}
    record = destination.parent / 'base-manifest.json'
    record.write_text(json.dumps(manifest, indent=2)+'\n')
    # Metadata first allows offline tokenizer checks while large weights transfer.
    metadata = [f['path'] for f in files if not f['path'].endswith('.safetensors')]
    for allowed in (metadata, [f['path'] for f in files if f['path'].endswith('.safetensors')]):
        snapshot_download(config['model_name_or_path'], revision=info.sha, token=False,
                          local_dir=destination, allow_patterns=allowed, max_workers=2)
    for item in files:
        verify_artifact(destination, item)
        item['verified'] = True
        record.write_text(json.dumps(manifest, indent=2)+'\n')
    manifest.update(verified=True, completed_at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat())
    record.write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'revision':info.sha, 'verified_files':len(files),
                      'bytes':sum(f['bytes'] for f in files)}), flush=True)


if __name__ == '__main__':
    config = json.loads(Path('/workspace/finetuning/config.qwen36-thor.json').read_text())
    download(config, '/workspace/base')
