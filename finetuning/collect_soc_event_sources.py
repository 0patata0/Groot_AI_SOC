"""Bounded, pinned acquisition of vendor/community SOC recording evidence.

Only metadata-linked data is fetched. Source commands are never executed. LFS
pointers are resolved against the pinned commit and verified against their OID.
Large files stay in the exclusion ledger; no silently truncated event files.
"""
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlparse, unquote
from urllib.request import Request, urlopen
import yaml
from collect_defensive_sources import safe_path, verify_blob, write, now, sha

REPOS = {'splunk_attack': 'splunk/attack_data', 'otrf': 'OTRF/Security-Datasets'}
FILE_LIMIT = 16 * 1024**2
TOTAL_LIMIT = 384 * 1024**2
EXTENSIONS = ('.log', '.json', '.jsonl', '.ndjson', '.zip', '.csv', '.txt')


def fetch(url, limit):
    ctx = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').exists() else None)
    with urlopen(Request(url, headers={'User-Agent': 'Groot-SOC-source-review/1.0',
                                      'Accept-Encoding': 'identity'}), context=ctx, timeout=60) as r:
        if urlparse(r.url).hostname not in ('raw.githubusercontent.com', 'media.githubusercontent.com'):
            raise ValueError('Unexpected download redirect')
        b = r.read(limit+1)
    if len(b) > limit: raise ValueError('Source exceeds declared bound')
    return b


def pinned_path(value, repo):
    if not isinstance(value, str): return None
    if value.startswith('/datasets/'): return str(safe_path(value.lstrip('/')))
    u = urlparse(value)
    if u.scheme != 'https' or u.netloc not in ('raw.githubusercontent.com', 'github.com'): return None
    prefix = '/' + repo + ('/blob/' if u.netloc == 'github.com' else '/')
    if not u.path.startswith(prefix): return None
    parts = unquote(u.path[len(prefix):]).split('/', 1)
    if len(parts) != 2: return None
    return str(safe_path(parts[1]))


def lfs_pointer(data):
    match = re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n?', data)
    if data.startswith(b'version https://git-lfs.') and not match:
        raise ValueError('Invalid LFS pointer')
    return {'sha256': match[1].decode(), 'bytes': int(match[2])} if match else None


def plan(root):
    root = Path(root)
    pins = {x['id']: x for x in json.loads((root/'pins.json').read_text())}
    acquisition = json.loads((root/'acquisition.json').read_text())
    # Rehash metadata before interpreting paths; collector receipts are evidence.
    entries = acquisition.get('files', acquisition.get('results', []))
    if not isinstance(entries, list): raise ValueError('Unexpected acquisition schema')
    cases = []; paths = defaultdict(list); held = []
    for entry in entries:
        key = entry['source']; path = entry['path']
        if key not in REPOS or not path.endswith(('.yaml', '.yml')): continue
        raw = (root/'raw'/key/path).read_bytes()
        if sha(raw) != entry['sha256']: raise ValueError('Metadata changed')
        obj = yaml.safe_load(raw)
        if not isinstance(obj, dict) or not obj.get('id'):
            held.append({'source': key, 'path': path, 'reason': 'missing_case_id'}); continue
        source_id = key + ':' + str(obj['id'])
        cid = source_id + ':' + sha(path.encode())[:12]
        files = obj.get('datasets', []) if key == 'splunk_attack' else obj.get('files', [])
        linked = []
        for item in files or []:
            p = pinned_path(item.get('path') if key == 'splunk_attack' else item.get('link'), REPOS[key])
            if p and p.endswith(EXTENSIONS):
                linked.append(p); paths[(key, p)].append(cid)
            else: held.append({'case_id': cid, 'reason': 'unsupported_or_external_data_reference'})
        cases.append({'id': cid, 'provider_id': source_id, 'source': key, 'source_path': path, 'source_sha256': entry['sha256'],
                      'title': obj.get('title'), 'description': obj.get('description'),
                      'author': obj.get('author', obj.get('contributors')),
                      'platform': obj.get('platform'), 'environment': obj.get('environment', (obj.get('simulation') or {}).get('environment')),
                      'provider_techniques': obj.get('mitre_technique', obj.get('attack_mappings')),
                      'files': linked, 'provider_per_event_verdict': False, 'training_admitted': False})
    if len({x['id'] for x in cases}) != len(cases): raise ValueError('Duplicate source case IDs')
    trees = {k:{x['path']:x for x in json.loads((root/(k+'-tree.json')).read_text())['tree'] if x['type']=='blob'} for k in REPOS}
    def one(pair):
        (key, path), ids = pair; item = trees[key].get(path)
        if not item or item['mode'] not in ('100644', '100755'): return {'source':key,'path':path,'reason':'missing_regular_pinned_blob'}
        pin = pins[key]; url = 'https://raw.githubusercontent.com/'+REPOS[key]+'/'+pin['commit']+'/'+path
        result = {'source':key,'path':path,'case_ids':sorted(ids),'git_blob':item['sha'],'commit':pin['commit'],
                  'git_bytes':item['size'],'bytes':item['size'],'url':url,'lfs':False}
        if item['size'] <= 1024:
            cache = root/'pointers'/key/path
            data = cache.read_bytes() if cache.exists() else fetch(url, 1024)
            verify_blob(data, item)
            cache.parent.mkdir(parents=True, exist_ok=True); cache.write_bytes(data)
            pointer = lfs_pointer(data)
            if pointer: result.update(pointer); result['lfs']=True; result['url']='https://media.githubusercontent.com/media/'+REPOS[key]+'/'+pin['commit']+'/'+path
        return result
    all_files=[];errors=[]
    with ThreadPoolExecutor(max_workers=6) as pool:
        fs={pool.submit(one, p):p[0] for p in sorted(paths.items())}
        for future in as_completed(fs):
            try: all_files.append(future.result())
            except Exception as e:
                key,p=fs[future]; errors.append({'source':key,'path':p,'reason':type(e).__name__})
            if (len(all_files)+len(errors))%200==0: print(json.dumps({'phase':'resolve','resolved':len(all_files),'errors':len(errors)}),flush=True)
    # Metadata is available for every discovered case. Prioritize local SOC concerns,
    # then broaden coverage through the remaining smallest complete recordings.
    def order(x):
        p=x['path'].lower()
        priority=0 if any(k in p for k in ('linux','auditd','log4','dns','firewall','nginx','apache','benign','suricata','network','systemd')) else 1
        return priority, x.get('bytes',0), x['source'], x['path']
    chosen=[];used=0
    for item in sorted(all_files,key=order):
        reason=item.get('reason')
        if not reason and item['bytes']>FILE_LIMIT: reason='per_file_bound_reference_only'
        if not reason and used+item['bytes']>TOTAL_LIMIT: reason='collection_byte_budget_reference_only'
        if reason: held.append({**item,'reason':reason});continue
        chosen.append(item);used+=item['bytes']
    report={'at_kst':now(),'cases':cases,'files':chosen,'held':held,'errors':errors,
            'selected_bytes':used,'file_limit':FILE_LIMIT,'total_limit':TOTAL_LIMIT,'training_admitted':0}
    write(root/'event-plan.json',report)
    return {'cases':len(cases),'files':len(chosen),'bytes':used,'held':len(held),'errors':len(errors)}


def collect(root):
    root=Path(root);p=json.loads((root/'event-plan.json').read_text());results=[];errors=[]
    def one(item):
        path=root/'events'/item['source']/str(safe_path(item['path']))
        if path.is_symlink() or not path.resolve().is_relative_to((root/'events').resolve()):raise ValueError('Unsafe destination')
        data=path.read_bytes() if path.exists() else fetch(item['url'],item['bytes'])
        if len(data)!=item['bytes']:raise ValueError('Size mismatch')
        if item['lfs']:
            if sha(data)!=item['sha256']:raise ValueError('LFS OID mismatch')
        else:verify_blob(data,{'size':item['bytes'],'sha':item['git_blob']})
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        return {**item,'sha256':sha(data),'stored_path':str(path.relative_to(root)),'verified':True}
    with ThreadPoolExecutor(max_workers=6)as pool:
        fs={pool.submit(one,item):item for item in p['files']}
        for f in as_completed(fs):
            try:results.append(f.result())
            except Exception as e:errors.append({'source':fs[f]['source'],'path':fs[f]['path'],'error':type(e).__name__})
            if (len(results)+len(errors))%100==0:print(json.dumps({'phase':'events','files':len(results),'errors':len(errors)}),flush=True)
    report={'at_kst':now(),'files':sorted(results,key=lambda x:(x['source'],x['path'])),'errors':errors,
            'bytes':sum(x['bytes']for x in results),'source_code_executed':False,'training_admitted':0}
    write(root/'event-acquisition.json',report)
    return {'files':len(results),'bytes':report['bytes'],'errors':len(errors)}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--phase',choices=('plan','collect'),required=True)
    a=p.parse_args();print(json.dumps((plan if a.phase=='plan'else collect)(a.root),ensure_ascii=False))
