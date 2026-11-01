"""Collect bounded, pinned research traces as inert data, never training gold.

No PCAPs, upstream programs or environment installers are downloaded/executed.
HF Git/LFS object hashes, byte limits and local re-read checks are enforced.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from collect_defensive_sources import now, sha, safe_path, write

REPO = 'maureille/agentic-pcap'
REVISION = '54ce8ca45a3fe2566d3b0daa54941427ab642797'
PREFIX = ('artifacts/primary_runs/ALL_MODELS/vllm--qwen3.6-35b-a3b-bf16/'
          'qwen3.6-35b-a3b-bf16-no-thinking-batch-1/P0_signature')
LIMIT = 16 * 1024 * 1024


def checked_root(root):
    root = Path(root).resolve()
    if not root.name.startswith('data-'):
        raise ValueError('Use an ignored data-* folder')
    root.mkdir(parents=True, exist_ok=True)
    return root


def fetch(url, limit):
    if urlsplit(url).hostname != 'huggingface.co' or not url.startswith('https://'):
        raise ValueError('Unapproved source URL')
    context = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').is_file() else None)
    with urlopen(Request(url, headers={'User-Agent': 'Groot-SOC-source-review/1.0',
                                      'Accept-Encoding': 'identity'}), context=context, timeout=30) as r:
        host = urlsplit(r.url).hostname or ''
        if urlsplit(r.url).scheme != 'https' or not (host == 'huggingface.co' or host.endswith('.huggingface.co')
                                                    or host.endswith('.xethub.hf.co') or host.endswith('.cdn.hf.co')):
            raise ValueError('Unexpected asset redirect')
        data = r.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Asset exceeds byte limit')
        return data, r.headers.get('Link')


def verify(data, item):
    if len(data) != item['size'] or len(data) > LIMIT:
        raise ValueError('Asset size mismatch')
    if item.get('lfs'):
        if sha(data) != item['lfs']['oid'] or item['lfs']['size'] != len(data):
            raise ValueError('LFS object mismatch')
    else:
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if blob != item['oid']:
            raise ValueError('Git object mismatch')


def selected(item):
    p = item['path']
    return item['type'] == 'file' and (
        p in ('README.md', 'LICENSE', 'CITATION.cff', 'SHA256SUMS',
              'metadata/captures.csv', 'metadata/condition_summary.csv')
        or p.startswith(PREFIX + '/no_thinking/') and p.endswith(('/session_export.json', '/final_answer.txt')))


def plan(root):
    root = checked_root(root)
    metadata = root / 'traces'
    metadata.mkdir(exist_ok=True)
    items = []
    for name, path in [('root', ''), ('captures', '/metadata'), ('sessions', '/'+PREFIX)]:
        url = f'https://huggingface.co/api/datasets/{REPO}/tree/{REVISION}{path}?recursive=true'
        # Root recursion would fetch all 4,752 runs; root metadata only.
        if name == 'root':
            url = url.removesuffix('?recursive=true')
        data, link = fetch(url, 4 * 1024 * 1024)
        if link and 'rel="next"' in link:
            raise ValueError('Incomplete asset tree; review pagination before collection')
        value = json.loads(data)
        write(metadata / (name+'-tree.json'), value)
        items.extend(x for x in value if selected(x))
    if len({x['path'] for x in items}) != len(items):
        raise ValueError('Duplicate asset paths')
    if len(items) > 100 or sum(x['size'] for x in items) > 32 * 1024 * 1024:
        raise ValueError('Trace collection exceeds explicit bound')
    write(metadata / 'selection.json', {'repo': REPO, 'revision': REVISION, 'files': items})
    return {'files': len(items), 'bytes': sum(x['size'] for x in items), 'pcaps_downloaded': 0}


def collect(root):
    root = checked_root(root)
    p = root / 'traces'
    selection = json.loads((p/'selection.json').read_text())
    if selection['repo'] != REPO or selection['revision'] != REVISION:
        raise ValueError('Unexpected source pin')
    trees = [json.loads((p/(name+'-tree.json')).read_text()) for name in ('root', 'captures', 'sessions')]
    expected = {x['path']: x for tree in trees for x in tree if selected(x)}
    items = selection['files']
    if len(items) > 100 or sum(x['size'] for x in items) > 32 * 1024 * 1024:
        raise ValueError('Trace collection exceeds explicit bound')
    for item in items:
        safe_path(item['path'])
        if expected.get(item['path']) != item or not 0 <= item['size'] <= LIMIT:
            raise ValueError('Selection differs from source tree')
    def one(item):
        dest = p/'raw'/str(safe_path(item['path']))
        if dest.is_symlink() or not dest.resolve().is_relative_to((p/'raw').resolve()):
            raise ValueError('Unsafe output path')
        url = f'https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/'+quote(item['path'], safe='/')
        data = dest.read_bytes() if dest.exists() else fetch(url, item['size'])[0]
        verify(data, item)
        data.decode('utf-8')
        if dest.suffix == '.json':
            json.loads(data)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            dest.write_bytes(data)
        if sha(dest.read_bytes()) != sha(data):
            raise ValueError('Stored file changed')
        return {'path': item['path'], 'url': url, 'bytes': len(data), 'sha256': sha(data),
                'source_object_verified': True, 'training_admitted': False}
    results, errors = [], []
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = {pool.submit(one, item): item for item in items}
        for future in as_completed(pending):
            try:
                results.append(future.result())
            except Exception as e:
                errors.append({'path': pending[future]['path'], 'error_type': type(e).__name__})
    receipt = {'at_kst': now(), 'repo': REPO, 'revision': REVISION,
               'files': sorted(results, key=lambda x: x['path']), 'errors': errors,
               'bytes': sum(x['bytes'] for x in results), 'pcaps_downloaded': 0,
               'license': 'CC-BY-4.0 for experimental artifacts per retained author card and LICENSE',
               'nature': 'Model-generated investigation traces in an emulated testbed; not expert gold or peer-review-certified answers',
               'training_admitted': 0}
    write(p/'acquisition.json', receipt)
    return {'files': len(results), 'bytes': receipt['bytes'], 'errors': errors, 'training_admitted': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--phase', choices=('plan', 'collect'), required=True)
    args = parser.parse_args()
    print(json.dumps(plan(args.root) if args.phase == 'plan' else collect(args.root)))
