"""Collect pinned official SOC references and audit on arrival; never execute inputs.

Raw files, derived candidates and manifests belong in an ignored data-* folder.
This is source review, not SFT admission, model training or device validation.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import ssl
import time
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

ALLOWED_REPOS = {'crs': 'coreruleset/coreruleset', 'wazuh': 'wazuh/wazuh',
                 'suricata_verify': 'OISF/suricata-verify',
                 'modsecurity_docs': 'owasp-modsecurity/documentation',
                 'nist_controls': 'usnistgov/oscal-content',
                 'cisa_counter': 'cisagov/coun7er',
                 'microsoft_aces': 'microsoft/ACESEvals',
                 'cti_realm': 'microsoft/ACESEvals',
                 'splunk_attack': 'splunk/attack_data',
                 'otrf': 'OTRF/Security-Datasets'}
LIMIT = 16 * 1024 * 1024


def sha(data): return hashlib.sha256(data).hexdigest()
def now(): return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()
def write(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)


def safe_path(name):
    p = PurePosixPath(name)
    if not name or str(p) != name or p.is_absolute() or '..' in p.parts or '\\' in name:
        raise ValueError('Unsafe source path')
    return p


def verify_blob(data, item):
    if len(data) != item['size'] or len(data) > LIMIT: raise ValueError('Source size mismatch')
    actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if actual != item['sha']: raise ValueError('Source does not match pinned Git blob')


def arrival_review(data, name):
    text = data.decode('utf-8')
    result = {'utf8': True, 'nul_bytes': '\x00' in text}
    if name.endswith(('.yaml', '.yml')):
        import yaml
        # Parse only data; never use unsafe YAML constructors or execute test commands.
        value = yaml.safe_load(text)
        result['yaml_mapping'] = isinstance(value, dict)
    if name.endswith('.json'):
        json.loads(text); result['json_valid'] = True
    return result


def select_path(source, path):
    if path in ('LICENSE','LICENSE.txt','LICENSE.md','README.md'): return True
    if source == 'splunk_attack':
        return path.startswith('datasets/') and path.endswith('.yml') and path != 'datasets/TEMPLATE.yml'
    if source == 'otrf':
        return path.startswith(('datasets/atomic/_metadata/', 'datasets/compound/_metadata/')) and path.endswith('.yaml')
    if source == 'cti_realm':
        return path == 'NOTICE.md' or path == 'domains/cti_realm/README.md' or path.startswith('domains/cti_realm/tasks/') and path.endswith(('.yaml', '.md'))
    if source == 'crs':
        return (path.startswith('tests/regression/tests/') and path.endswith('.yaml') or
                path.startswith('rules/') and path.endswith('.conf') or path == 'crs-setup.conf.example')
    if source == 'wazuh':
        return (path.startswith('ruleset/testing/tests/') and path.endswith('.ini') or
                path.startswith(('ruleset/rules/','ruleset/decoders/','ruleset/testing/ruleset/')) and path.endswith('.xml') or
                path == 'ruleset/testing/runtests.py')
    if source == 'modsecurity_docs': return path.startswith('content/') and path.endswith('.md')
    if source == 'nist_controls': return path == 'nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json'
    if source == 'cisa_counter':
        return path.startswith('countermeasures/') and path.endswith('.md') or path in ('CMCategories.md','CountermeasureTitleIntendedOutcome.md')
    if source == 'microsoft_aces':
        if path in ('NOTICE.md', 'domains/excytin/setup.py', 'domains/excytin/tasks/global.yaml'):
            return True
        if path.startswith(('domains/excytin/tasks/latest_train_set/',
                            'domains/excytin/tasks/latest_test_set/')):
            return path.endswith('.yaml')
        if path.startswith('domains/eval_ranges/'):
            roles = ('detection', 'posture_analysis', 'remediation', 'threat_intel')
            return ('/tasks/' in path and any(path.endswith('_'+role+'.yaml') for role in roles)
                    or '/data/' in path and path.endswith(('base_infrastructure.yaml', 'azure_log_schemas.yaml'))
                    or '/inputs/attack_corpus/' in path and path.endswith('.json'))
    return False


def plan(root, spec_path):
    root = Path(root).resolve()
    if not root.name.startswith('data-'): raise ValueError('Use an ignored data-* folder')
    root.mkdir(parents=True, exist_ok=True)
    pins = json.loads(Path(spec_path).read_text())['source_pins']; selected = {}
    context = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').is_file() else None)
    for pin in pins:
        if ALLOWED_REPOS.get(pin['id']) != pin['repo'] or not re.fullmatch('[0-9a-f]{40}', pin['commit']):
            raise ValueError('Unapproved source')
        for suffix, endpoint in [('commit', '/commits/'+pin['commit']), ('tree', '/git/trees/'+pin['tree']+'?recursive=1')]:
            path = root/(pin['id']+'-'+suffix+'.json')
            if path.exists(): value=json.loads(path.read_text())
            else:
                url='https://api.github.com/repos/'+pin['repo']+endpoint
                with urlopen(Request(url,headers={'User-Agent':'Groot-SOC-source-review/1.0'}),context=context,timeout=45) as resp:
                    if not resp.url.startswith('https://api.github.com/'): raise ValueError('Unexpected metadata redirect')
                    data=resp.read(LIMIT+1)
                if len(data)>LIMIT: raise ValueError('Metadata exceeds bound')
                value=json.loads(data);write(path,value)
            if suffix=='commit':
                if value['sha']!=pin['commit'] or value['commit']['tree']['sha']!=pin['tree']:
                    raise ValueError('Commit/tree mismatch')
            else:
                if value['sha']!=pin['tree'] or value.get('truncated'): raise ValueError('Incomplete source tree')
                selected[pin['id']]=[x for x in value['tree'] if x['type']=='blob' and select_path(pin['id'],x['path'])]
    write(root/'pins.json',pins);write(root/'selection.json',selected)
    return {'phase':'planned','files':{k:len(v) for k,v in selected.items()},'training_started':False}


def collect(root):
    root = Path(root).resolve()
    if not root.name.startswith('data-'): raise ValueError('Use an ignored data-* folder')
    pins = {x['id']: x for x in json.loads((root/'pins.json').read_text())}
    selected = json.loads((root/'selection.json').read_text())
    context = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').is_file() else None)
    tasks = []
    for key, rows in selected.items():
        pin = pins[key]
        if pin['repo'] != ALLOWED_REPOS[key] or not re.fullmatch('[0-9a-f]{40}',pin['commit']):
            raise ValueError('Unapproved or unpinned source')
        tree = json.loads((root/(key+'-tree.json')).read_text())
        if tree.get('truncated') or tree['sha'] != pin['tree']: raise ValueError('Incomplete source tree')
        expected = {x['path']: x for x in tree['tree'] if x['type']=='blob'}
        for item in rows:
            safe_path(item['path'])
            if expected.get(item['path']) != item or item['mode'] not in ('100644', '100755'):
                raise ValueError('Selection differs from pinned source tree')
            if not 0 <= item['size'] <= LIMIT: raise ValueError('Source exceeds per-file bound')
            tasks.append((key, pin, item))
    if len(tasks) > 2000 or sum(x[2]['size'] for x in tasks) > 64*1024*1024:
        raise ValueError('Explicit collection budget exceeded')
    results = []; errors = []
    def fetch(task):
        key, pin, item = task
        dest = root/'raw'/key/str(safe_path(item['path']))
        if not dest.resolve().is_relative_to(root/'raw') or dest.is_symlink():
            raise ValueError('Unsafe output path')
        url = 'https://raw.githubusercontent.com/'+pin['repo']+'/'+pin['commit']+'/'+item['path']
        if dest.exists(): data = dest.read_bytes(); reused = True
        else:
            with urlopen(Request(url, headers={'User-Agent':'Groot-SOC-source-review/1.0',
                                              'Accept-Encoding':'identity'}), context=context, timeout=45) as resp:
                if not resp.url.startswith('https://raw.githubusercontent.com/'): raise ValueError('Unexpected redirect')
                data = resp.read(min(LIMIT, item['size']) + 1)
            reused = False
        verify_blob(data, item)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not reused: dest.write_bytes(data)
        try: review = arrival_review(data, item['path'])
        except Exception as error: review = {'parse_error_type':type(error).__name__, 'quarantined':True}
        return {'source':key,'path':item['path'],'url':url,'commit':pin['commit'],
                'bytes':len(data),'sha256':sha(data),'git_blob':item['sha'],
                'git_blob_verified':True,'reused_verified_file':reused,'arrival_review':review}
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(fetch,t):t for t in tasks}
        for fut in as_completed(futures):
            key, pin, item = futures[fut]
            try: results.append(fut.result())
            except Exception as error: errors.append({'source':key,'path':item['path'],'error_type':type(error).__name__})
            if (len(results)+len(errors)) % 100 == 0:
                print(json.dumps({'at_kst':now(),'files_verified':len(results),'errors':len(errors)}),flush=True)
    report = {'at_kst':now(),'status':'completed' if not errors else 'partial',
              'scope':'source_acquisition_and_arrival_checks_not_training_admission',
              'files':sorted(results,key=lambda x:(x['source'],x['path'])),'errors':errors,
              'files_verified':len(results),'bytes_retained':sum(x['bytes'] for x in results),
              'seconds':time.monotonic()-started,'source_instructions_executed':False,
              'training_started':False,'production_changed':False}
    write(root/'acquisition.json',report)
    return {k:v for k,v in report.items() if k not in ('files',)}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
    p.add_argument('--phase',choices=('plan','collect','review'),default='collect')
    p.add_argument('--spec',type=Path,default=Path(__file__).with_name('DEFENSIVE_SOURCE_SPEC.json'))
    args=p.parse_args()
    if args.phase=='plan': result=plan(args.root,args.spec)
    elif args.phase=='review':
        from review_defensive_sources import review
        result=review(args.root)
    else: result=collect(args.root)
    print(json.dumps(result,ensure_ascii=False))
