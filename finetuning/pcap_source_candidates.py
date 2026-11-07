"""Collect and inspect reviewed CTU-13 flow sources locally, never train/replay.

The output is evidence candidates, not model-ready conversations. Provider
labels stay outside observations; background and inbound botnet traffic must
not be relabeled as confirmed malicious. No malware binaries are downloaded.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import heapq
import ipaddress
import json
from pathlib import Path
import re
import ssl
import subprocess
import time
import urllib.request
from zoneinfo import ZoneInfo

CASES = {
    'ctu13-05': (46, 'capture20110815-2.binetflow', 'Virut'),
    'ctu13-07': (48, 'capture20110816-2.binetflow', 'Sogou'),
    'ctu13-11': (52, 'capture20110818-2.binetflow', 'RBot'),
}
FIELDS = ['StartTime','Dur','Proto','SrcAddr','Sport','Dir','DstAddr','Dport',
          'State','sTos','dTos','TotPkts','TotBytes','SrcBytes','Label']
LIMIT = 64 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stamp():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def category(label):
    # A botnet dataset is not an all-malicious label for every flow.
    if 'From-Botnet' in label:
        return 'provider_botnet_origin'
    if 'From-Normal' in label:
        if any(word in label for word in ('DNS','WebServer','MatLab')):
            return 'provider_normal_server_low_confidence'
        return 'provider_normal_origin'
    if 'To-Botnet' in label:
        return 'inbound_to_botnet_not_confirmed_malicious'
    if 'To-Normal' in label:
        return 'inbound_to_normal_not_confirmed_benign'
    if 'Background' in label:
        return 'background_unresolved'
    if label.startswith('flow=Normal-'):
        return 'provider_normal_activity_direction_unspecified'
    return 'unrecognized_label_hold'


def validate_row(row):
    if set(row) != set(FIELDS) or any(v is None for v in row.values()):
        return 'malformed_columns'
    try:
        for key in ('SrcAddr', 'DstAddr'):
            if row['Proto'] in ('arp', 'rarp', 'ipx/spx'):
                try:
                    ipaddress.ip_address(row[key])
                except ValueError:
                    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', row[key]):
                        raise ValueError('invalid link-layer address')
            else:
                ipaddress.ip_address(row[key])
        duration = Decimal(row['Dur'])
        if not duration.is_finite() or duration < 0:
            raise ValueError('invalid duration')
        if not all(re.fullmatch(r'\d+', row[k]) for k in ('TotPkts','TotBytes','SrcBytes')):
            raise ValueError('invalid counters')
        if int(row['SrcBytes']) > int(row['TotBytes']):
            raise ValueError('inconsistent counters')
        datetime.strptime(row['StartTime'], '%Y/%m/%d %H:%M:%S.%f')
    except (ValueError, InvalidOperation):
        return 'measurement_or_address'
    return None


def collect(root, native_curl=False):
    root = Path(root).resolve()
    raw = root / 'raw'
    raw.mkdir(parents=True, exist_ok=True)
    urls = []
    for case, (capture, filename, _) in CASES.items():
        base = f'https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-{capture}/'
        urls.extend([(case + '/README.md', base + 'README.md'),
                     (case + '/' + filename, base + 'detailed-bidirectional-flow-labels/' + filename)])
    context = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').is_file() else None)

    def fetch(item):
        name, url = item
        path = raw / name
        if path.exists():
            raise ValueError('existing source refused; verify old manifest instead')
        path.parent.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        if native_curl:
            # macOS curl uses the OS trust store; never use -k/insecure or add a CA.
            partial = path.with_name(path.name+'.part')
            header = path.with_name(path.name+'.headers')
            if partial.exists() or header.exists(): raise ValueError('partial source requires review')
            result = subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--proto','=https',
                '--connect-timeout','15','--max-time','180','--max-filesize',str(LIMIT),
                '--output',str(partial),'--dump-header',str(header),
                '--write-out','%{http_code}\n%{url_effective}\n%{size_download}\n',url],
                capture_output=True,text=True,timeout=190)
            if result.returncode: raise ValueError('verified native HTTPS fetch failed: '+result.stderr[:180])
            status,effective,size = result.stdout.strip().splitlines()
            if status!='200' or effective!=url: raise ValueError('source response/redirect mismatch')
            data = partial.read_bytes()
            if len(data)>LIMIT or len(data)!=int(size): raise ValueError('incomplete native HTTPS source')
            data.decode('utf-8','strict')
            headers = dict(line.split(': ',1) for line in header.read_text().splitlines() if ': ' in line)
            partial.replace(path); header.unlink()
            return {'path':name,'url':url,'bytes':len(data),'sha256':sha(data),
                    'downloaded_at_kst':stamp(),'headers':{k:headers.get(k) for k in ('Last-Modified','ETag','Content-Type')},
                    'upstream_sha256':None,'tls_verification':'macOS native curl trust store; verified, no redirect'}
        request = urllib.request.Request(url, headers={'User-Agent':'Groot-SOC-source-review/1.0','Accept-Encoding':'identity'})
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            if response.url != url:
                raise ValueError('unexpected source redirect')
            expected = int(response.headers['Content-Length']) if response.headers.get('Content-Length') else None
            if expected is not None and expected > LIMIT:
                raise ValueError('source exceeds collection limit')
            data = bytearray()
            while True:
                if time.monotonic() - started > 180:
                    raise TimeoutError('source collection deadline')
                chunk = response.read(256*1024)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > LIMIT:
                    raise ValueError('source exceeds collection limit')
            if expected is not None and len(data) != expected:
                raise ValueError('incomplete source')
            headers = {k:response.headers.get(k) for k in ('Last-Modified','ETag','Content-Type')}
        data.decode('utf-8', 'strict')
        with path.open('xb') as f:
            f.write(data)
        return {'path':name,'url':url,'bytes':len(data),'sha256':sha(data),
                'downloaded_at_kst':stamp(),'headers':headers,'upstream_sha256':None}

    with ThreadPoolExecutor(max_workers=3) as pool:
        sources = list(pool.map(fetch, urls))
    (root/'source_manifest.json').write_text(json.dumps({'sources':sources,'at_kst':stamp()},ensure_ascii=False,indent=2)+'\n')
    return {'files':len(sources),'bytes':sum(r['bytes'] for r in sources),'training_started':False}


def inspect(root):
    root = Path(root).resolve()
    manifest = json.loads((root/'source_manifest.json').read_text())
    sources = {r['path']:r for r in manifest['sources']}
    summaries = []
    for case, (_, filename, family) in CASES.items():
        path = root/'raw'/case/filename
        raw = path.read_bytes()
        assert sha(raw) == sources[case+'/'+filename]['sha256']
        labels = Counter(); categories = Counter(); protocols = Counter(); rows = 0
        invalid = Counter(); duplicates = 0; seen = set(); sample = defaultdict(list)
        with path.open(newline='',encoding='utf-8') as f:
            reader = csv.DictReader(f)
            if reader.fieldnames != FIELDS:
                raise ValueError('unrecognized CTU bidirectional flow schema')
            for line, row in enumerate(reader, 2):
                rows += 1
                error = validate_row(row)
                if error:
                    invalid[error] += 1; continue
                encoded = json.dumps(row,sort_keys=True,separators=(',',':')).encode()
                key = sha(encoded)
                if key in seen:
                    duplicates += 1; continue
                seen.add(key)
                label = row['Label']; group = category(label)
                labels[label] += 1; categories[group] += 1; protocols[row['Proto']] += 1
                # Deterministic hash ranking avoids selecting only the first seconds.
                entry = (-int(key,16),line,row)
                if len(sample[group])<100: heapq.heappush(sample[group],entry)
                elif entry[0]>sample[group][0][0]: heapq.heapreplace(sample[group],entry)
        summaries.append({'case':case,'family':family,'source':sources[case+'/'+filename],
                          'rows':rows,'unique_valid_rows':len(seen),'duplicates':duplicates,
                          'invalid':dict(invalid),'labels':dict(labels),'categories':dict(categories),
                          'protocols':dict(protocols),
                          'selected':{g:sorted((f'{-key:064x}',line,row) for key,line,row in values)
                                      for g,values in sample.items()}})
    (root/'inspection.json').write_text(json.dumps(summaries,ensure_ascii=False,indent=2)+'\n')
    return [{k:v for k,v in r.items() if k not in ('selected','labels')} for r in summaries]


def transformed(case, line, row):
    """Keep provider conclusions out of observations and retain source coordinates."""
    if validate_row(row):
        raise ValueError('invalid source row')
    identifier = f'{case}-L{line}'
    endpoints = {k:'host-'+sha(('ctu13-endpoint-v1:'+row[k]).encode())[:24]
                 for k in ('SrcAddr','DstAddr')}
    observation = {
        'id':identifier,
        'observed_at_source':datetime.strptime(row['StartTime'], '%Y/%m/%d %H:%M:%S.%f').isoformat(),
        'source_timezone':'unverified',
        'duration_seconds':row['Dur'], 'protocol':row['Proto'],
        'source_endpoint':endpoints['SrcAddr'], 'source_port_raw':row['Sport'],
        'destination_endpoint':endpoints['DstAddr'], 'destination_port_raw':row['Dport'],
        'direction_raw':row['Dir'], 'state_raw':row['State'],
        'source_tos_raw':row['sTos'], 'destination_tos_raw':row['dTos'],
        'packets':int(row['TotPkts']), 'bytes':int(row['TotBytes']),
        'source_bytes':int(row['SrcBytes']),
    }
    label = row['Label']
    reference = {
        'id':identifier, 'source_line':line,
        'source_row_sha256':sha(json.dumps(row,sort_keys=True,separators=(',',':')).encode()),
        'provider_label_sha256':sha(label.encode()), 'category':category(label),
        'provider_activity':re.sub(r'^flow=From-Botnet-V\d+-(?:\d+-)?', '', label)
            if 'From-Botnet' in label else None,
        'judgment_source':'provider-label; not a new expert or model verdict',
    }
    return observation, reference


def curate(root):
    root = Path(root).resolve()
    sources = json.loads((root/'source_manifest.json').read_text())
    source_by_path = {x['path']:x for x in sources['sources']}
    output = root/'cleaned'/'datasets'/'ctu13-flow'/'20261107'
    output.mkdir(parents=True, exist_ok=False)
    summaries = []; all_observations = {}; exclusions = []
    for case, (capture, filename, family) in CASES.items():
        source = source_by_path[case+'/'+filename]
        path = root/'raw'/source['path']
        if sha(path.read_bytes()) != source['sha256']:
            raise ValueError('source changed since acquisition')
        counts = Counter(); seen = set(); start = None; end = None
        with path.open(newline='',encoding='utf-8') as f, \
             (output/(case+'.observations.jsonl')).open('x') as observations, \
             (output/(case+'.references.jsonl')).open('x') as references:
            reader = csv.DictReader(f)
            if reader.fieldnames != FIELDS: raise ValueError('unknown schema')
            for line, row in enumerate(reader, 2):
                counts['raw'] += 1
                error = validate_row(row)
                row_hash = sha(json.dumps(row,sort_keys=True,separators=(',',':')).encode())
                if error or row_hash in seen:
                    reason = error or 'exact_duplicate'
                    exclusions.append({'case':case,'source_line':line,'sha256':row_hash,'reason':reason})
                    counts[reason] += 1; continue
                if category(row['Label']) == 'unrecognized_label_hold':
                    exclusions.append({'case':case,'source_line':line,'sha256':row_hash,'reason':'unrecognized_label_hold'})
                    counts['unrecognized_label_hold'] += 1; continue
                seen.add(row_hash)
                observation, reference = transformed(case,line,row)
                semantic = dict(observation); semantic.pop('id')
                key = sha(json.dumps(semantic,sort_keys=True,separators=(',',':')).encode())
                if key in all_observations:
                    if all_observations[key] != reference['provider_label_sha256']:
                        raise ValueError('conflicting labels for same observation; review before export')
                    exclusions.append({'case':case,'source_line':line,'sha256':row_hash,'reason':'duplicate_observation_across_cases'})
                    counts['duplicate_observation_across_cases'] += 1; continue
                all_observations[key] = reference['provider_label_sha256']
                observations.write(json.dumps(observation,separators=(',',':'))+'\n')
                references.write(json.dumps(reference,separators=(',',':'))+'\n')
                counts['retained'] += 1; counts[reference['category']] += 1
                value = observation['observed_at_source']
                start = value if start is None else min(start,value)
                end = value if end is None else max(end,value)
        summaries.append({'case':case,'capture':capture,'probable_family_by_provider':family,
                          'source':source,'counts':dict(counts),'source_clock_first':start,
                          'source_clock_last':end,'timezone_status':'unverified; no fabricated KST conversion'})
    metadata = {
        'schema':'ctu13-curated-flow-candidate-v1','created_at_kst':stamp(),
        'status':'candidate_only','training_eligible':False,'training_started':False,
        'training_input_allowlist':[], 'split':'unassigned',
        'leakage_group':'CTU-13-shared-campus-and-hosts',
        'split_rule':'Keep this corpus and related derivatives together; no random flow split. Historical evaluation overlap requires final review before SFT.',
        'citation':{'authors':['Sebastian Garcia','Martin Grill','Jan Stiborek','Alejandro Zunino'],
                    'title':'An empirical comparison of botnet detection methods',
                    'journal':'Computers & Security','year':2014,'volume':45,'pages':'100-123',
                    'doi':'10.1016/j.cose.2014.05.011'},
        'permission':'Dataset README permits use with project/author attribution; official FAQ requires appropriate citation. No SPDX license inferred.',
        'permissions_url':'https://www.stratosphereips.org/datasets-faq',
        'source_kind':'University controlled malware captures with background and normal traffic, not three independently confirmed enterprise intrusions',
        'label_limits':['Botnet-origin does not prove every connection was an attack or succeeded.',
                        'Inbound, background and server labels are not confirmed benign/malicious.',
                        'Provider labels are stored in reference files and prohibited from inference inputs.'],
        'quality_notes':['Capture48 README contains an inconsistent Aug10/Neris passage; excluded from timeline/answer evidence.',
                         'README host flow totals differ from CSV row counts in some cases; CSV counts reported separately, not silently doubled.',
                         'Source clock timezone not established by CSV alone. README CEST annotations do not prove export clock settings.',
                         'Endpoint identifiers are deterministic pseudonyms, not irreversible anonymization. Raw labels/names/addresses stay in local original archive.'],
        'processing':{'script':'finetuning/pcap_source_candidates.py','sha256':sha(Path(__file__).read_bytes()),
                      'sampling':'none; all validated unique observations retained',
                      'labels':'separate references; provider origin and certainty retained'},
        'sources':sources['sources'],'cases':summaries,'excluded_rows':exclusions,
        'sft_conversations':0,'model_tokens_checked':False,
    }
    (output/'candidate_manifest.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2)+'\n')
    (output/'README.txt').write_text(
        'CTU-13 curated evidence candidates. NOT approved training input.\n'
        'Observations and provider references are separate. No labels, original IPs or malware family in observations.\n'
        'Sources, citation, processing hashes, caveats and exclusions: candidate_manifest.json.\n'
        'No packet payloads, PCAPs, executable malware, model weights or secrets.\n'
        'No training/validation/test split or SFT conversations assigned; automatic training allowlist is empty.\n'
        'Keep CTU-13 related captures together for leakage review. Source timestamps have unverified zone.\n')
    return {'cases':len(summaries),'source_rows':sum(x['counts']['raw'] for x in summaries),
            'retained':sum(x['counts']['retained'] for x in summaries),'excluded':len(exclusions),
            'training_eligible':False,'sft_conversations':0}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('operation', choices=('collect','inspect','curate'))
    ap.add_argument('root')
    ap.add_argument('--native-curl',action='store_true')
    args = ap.parse_args()
    result = collect(args.root,args.native_curl) if args.operation=='collect' else \
        inspect(args.root) if args.operation=='inspect' else curate(args.root)
    print(json.dumps(result,ensure_ascii=False))
