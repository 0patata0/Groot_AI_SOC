"""Audit official regression/reference records without executing tests or training.

Preserve provider assertions separately from inputs. Passing static linkage is
not a successful device replay, verified incident or training admission.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import yaml
from collect_defensive_sources import now, sha, verify_blob, write


def canonical(value): return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

def section_records(text):
    """Preserve each log occurrence, including duplicate INI log keys."""
    starts = list(re.finditer(r'^\[([^\n]+)\]\s*$', text, re.M))
    for i, match in enumerate(starts):
        block = text[match.end():starts[i+1].start() if i+1<len(starts) else len(text)]
        fields = {}; logs = []; unknown = []
        # Provider logs are single-line; reject unrecognized continuations instead of dropping them.
        for line in block.splitlines():
            if not line.strip() or line.lstrip().startswith((';', '#')): continue
            pair = re.match(r'^([^=]+?)\s*=\s*(.*)$', line)
            if not pair: unknown.append('unsupported_continuation'); continue
            key, value = pair.group(1).strip(), pair.group(2)
            if key.startswith('log '): logs.append((key, value))
            elif key in fields: unknown.append('duplicate_metadata')
            else: fields[key] = value.strip()
        yield match.group(1), fields, logs, unknown


def xml_rules(folder):
    index = defaultdict(list); errors = []
    for file in sorted(folder.rglob('*.xml')):
        if '/decoders/' in str(file) or 'decoder' in file.name: continue
        text = file.read_text()
        if '<!DOCTYPE' in text or '<!ENTITY' in text:
            errors.append(str(file.relative_to(folder))); continue
        try:
            root = ET.fromstring('<snapshot>'+re.sub(r'<\?xml.*?\?>','',text,flags=re.S)+'</snapshot>')
        except ET.ParseError:
            errors.append(str(file.relative_to(folder))); continue
        for rule in root.iter('rule'):
            if rule.get('id'):
                index[rule.get('id')].append({'path':str(file.relative_to(folder)),
                    'level':rule.get('level'),'frequency':rule.get('frequency'),
                    'timeframe':rule.get('timeframe'),
                    'dependencies':[{'kind':n.tag,'value':n.text} for n in rule
                                    if n.tag in ('if_sid','if_matched_sid','if_group','if_matched_group')]})
    return index, errors


def wazuh_records(text, source_path, index):
    for ordinal,(section, fields, logs, unknown) in enumerate(section_records(text),1):
        for number,(key, log) in enumerate(logs,1):
            reasons = list(unknown);rule=fields.get('rule','');level=fields.get('alert','')
            if not rule.isdecimal() or not level.isdecimal() or 'decoder' not in fields:
                reasons.append('incomplete_tuple_requires_engine_semantics')
            links=index.get(rule,[])
            if rule!='0' and not links: reasons.append('rule_definition_unresolved')
            if rule!='0' and links and not any(x['level']==level for x in links):
                reasons.append('expected_level_definition_mismatch')
            if not re.fullmatch(r'log\s+\d+\s+(pass|fail)',key): reasons.append('unsupported_log_key')
            if not log: reasons.append('empty_input')
            yield {'id':f'wazuh:{source_path}:{ordinal}:{number}','source':'wazuh',
                'source_path':source_path,'source_locator':{'section':section,'ordinal':ordinal,'log_ordinal':number,'log_key':key},
                'nature':'provider_regression_fixture_not_incident',
                'input':{'log':log},
                'target':{'predicate':'expected_tuple_matches' if key.endswith('pass') else 'expected_tuple_does_not_match',
                          'rule_id':rule,'level':level,'decoder':fields.get('decoder')},
                'rule_links':links,'family':source_path.split('/')[-1].split('.')[0],
                'failure_targets':['evidence_vs_inference','rule_scope','correlation_context'],
                'reasons':reasons,'engine_executed':False,
                'label_limit':'Negative case is tuple mismatch, not a benign verdict; logs run in separate provider subprocesses.'}


def crs_records(value, source_path, rule_ids):
    if not isinstance(value,dict): return
    for ordinal,test in enumerate(value.get('tests',[]),1):
        reasons=[];inputs=[];targets=[];stages=test.get('stages',[])
        if not stages: reasons.append('missing_stages')
        if test.get('skip'): reasons.append('provider_skip')
        for stage in stages:
            input_=stage.get('input');output=stage.get('output')
            if not isinstance(input_,dict) or not isinstance(output,dict) or not output:
                reasons.append('missing_input_or_expectation');continue
            log=output.get('log',{})
            for field in ('expect_ids','no_expect_ids'):
                if field in log:
                    if not isinstance(log[field],list): reasons.append('invalid_rule_ids');continue
                    if any(str(i) not in rule_ids for i in log[field]): reasons.append('rule_definition_unresolved')
            positive=set(map(str,log.get('expect_ids',[])));negative=set(map(str,log.get('no_expect_ids',[])))
            if positive & negative: reasons.append('contradictory_expected_rule')
            if output.get('status') is None and not log: reasons.append('unreviewed_output_predicate')
            inputs.append(input_);targets.append(output)
        yield {'id':f'crs:{source_path}:{test.get("test_id",ordinal)}','source':'crs',
            'source_path':source_path,'source_locator':{'test_id':test.get('test_id'),'ordinal':ordinal},
            'nature':'provider_regression_fixture_not_incident',
            'input':{'stages':inputs,'fixture_rule_id':value.get('rule_id'),
                     'test_configuration':{k:v for k,v in test.items() if k not in ('test_id','desc','stages','skip')}},
            'target':{'stage_assertions':targets},'family':source_path.split('/')[-2],
            'failure_targets':['waf_detection_vs_block','evidence_vs_inference'],
            'reasons':reasons,'engine_executed':False,
            'label_limit':'Expected rule logging is not blocking success or production compromise; preserve stage/configuration.'}


def deduplicate(rows):
    groups=defaultdict(list)
    for row in rows:
        fingerprint=sha(canonical([row['source'],row['input']]).encode())
        row['input_sha256']=fingerprint;row['target_sha256']=sha(canonical(row['target']).encode())
        groups[fingerprint].append(row)
    for values in groups.values():
        targets={x['target_sha256'] for x in values}
        if len(targets)>1:
            for row in values:row['reasons'].append('same_input_conflicting_assertions')
        elif len(values)>1:
            # Prefer a statically valid representative, preserving all source links in the audit.
            order=sorted(values,key=lambda x:(bool(x['reasons']),x['id']))
            for row in order[1:]:row['reasons'].append('duplicate_input_and_assertion');row['duplicate_of']=order[0]['id']
    # Connect families that share an input; a split cannot separate exact duplicates/conflicts.
    parent={r['source']+':'+r['family']:r['source']+':'+r['family'] for r in rows}
    def find(x):
        while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
        return x
    observable_groups=defaultdict(list)
    for row in rows:
        # Even tests about different rules sharing the same request stay in one partition.
        observable={k:v for k,v in row['input'].items() if k!='fixture_rule_id'}
        row['observable_sha256']=sha(canonical([row['source'],observable]).encode())
        observable_groups[row['observable_sha256']].append(row)
    for values in observable_groups.values():
        keys=[find(r['source']+':'+r['family']) for r in values];base=min(keys)
        for key in keys:parent[find(key)]=find(base)
    for row in rows:
        group=find(row['source']+':'+row['family']);row['split_group']=group
        row['static_status']='quarantined' if row['reasons'] else 'linked'
        row['training_admitted']=False
    # Reserve whole connected families near 20% by record count, deterministically.
    # Hash-only assignment was badly imbalanced for the small number of CRS families.
    counts=defaultdict(Counter)
    for row in rows:
        if not row['reasons']:counts[row['source']][row['split_group']]+=1
    reserved=set()
    for source, sizes in counts.items():
        target=sum(sizes.values())*.2; current=0
        for group,size in sorted(sizes.items(),key=lambda x:(-x[1],x[0])):
            if abs(current+size-target)<abs(current-target):reserved.add(group);current+=size
    for row in rows:
        row['provisional_partition']='reserved_evaluation' if row['split_group'] in reserved else 'training_candidate'
    return rows


def history_review(root, history_root):
    """Exact JSON string-value overlap only; never claim semantic/history completeness."""
    root=Path(root).resolve();history_root=Path(history_root).resolve();files=[];seen_files=set();strings=set();line_count=0
    def values(value):
        if isinstance(value,str):yield value
        elif isinstance(value,dict):
            for x in value.values():yield from values(x)
        elif isinstance(value,list):
            for x in value:yield from values(x)
    for file in sorted(history_root.glob('data-*/**/*.jsonl')):
        if root in file.resolve().parents or file.is_symlink():continue
        data=file.read_bytes();digest=sha(data);files.append({'path':str(file.relative_to(history_root)),'sha256':digest,'bytes':len(data)})
        if digest in seen_files:continue
        seen_files.add(digest)
        for line in data.decode().splitlines():
            if not line.strip():continue
            value=json.loads(line);line_count+=1
            for text in values(value):
                if len(text.strip())>=40:strings.add(sha(text.strip().encode()))
    matches=[];checked=0
    for line in (root/'review/regression-records.jsonl').read_text().splitlines():
        row=json.loads(line);texts=[x for x in values(row['input']) if len(x.strip())>=40]
        checked+=len(texts)
        if any(sha(x.strip().encode()) in strings for x in texts):matches.append(row['id'])
    result={'at_kst':now(),'files':files,'unique_file_contents':len(seen_files),'rows_read':line_count,
            'history_string_hashes':len(strings),'new_input_values_checked':checked,'matched_record_ids':matches,
            'scope':'Local retained JSONL exact string values >=40 characters, whitespace trimmed',
            'limitations':['Does not detect substrings, paraphrases or unretained server-only history',
                           'No proof of semantic novelty or final train/evaluation separation'],'training_admitted':0}
    write(root/'review/history-review.json',result);return result


def review(root):
    root=Path(root);acquisition=json.loads((root/'acquisition.json').read_text())
    if acquisition['status']!='completed' or acquisition['errors']:raise ValueError('Incomplete acquisition')
    files={(x['source'],x['path']):x for x in acquisition['files']}
    for item in files.values():
        data=(root/'raw'/item['source']/item['path']).read_bytes()
        if sha(data)!=item['sha256']:raise ValueError('Acquired source changed')
        verify_blob(data,{'size':item['bytes'],'sha':item['git_blob']})
    rows=[];wazuh=root/'raw/wazuh';index,xml_errors=xml_rules(wazuh/'ruleset')
    for file in sorted((wazuh/'ruleset/testing/tests').glob('*.ini')):
        rows.extend(wazuh_records(file.read_text(),str(file.relative_to(wazuh)),index))
    crs=root/'raw/crs';rule_ids=set()
    for file in (crs/'rules').glob('*.conf'):
        rule_ids.update(re.findall(r'\bid\s*:\s*[\'"]?(\d+)',file.read_text()))
    empty_yaml=[]
    for file in sorted((crs/'tests/regression/tests').rglob('*.yaml')):
        data=yaml.safe_load(file.read_text())
        if not isinstance(data,dict):empty_yaml.append(str(file.relative_to(crs)));continue
        rows.extend(crs_records(data,str(file.relative_to(crs)),rule_ids))
    rows=deduplicate(rows)
    for row in rows:
        item=files[(row['source'],row['source_path'])]
        row.update(source_sha256=item['sha256'],source_url=item['url'],source_commit=item['commit'])
    derived=root/'review';derived.mkdir(exist_ok=True)
    records=derived/'regression-records.jsonl'
    records.write_text(''.join(canonical(x)+'\n' for x in rows))
    knowledge=[]
    docs=root/'raw/modsecurity_docs'
    for file in sorted((docs/'content').rglob('*.md')):
        text=file.read_text();headings=list(re.finditer(r'^#{2,3}\s+(.+)\s*$',text,re.M))
        for i,m in enumerate(headings):
            body=text[m.start():headings[i+1].start() if i+1<len(headings) else len(text)].strip()
            if len(body)<80:continue
            path=str(file.relative_to(docs));knowledge.append({'source':'modsecurity_docs','source_path':path,
                'source_sha256':files[('modsecurity_docs',path)]['sha256'],'heading':m.group(1),'line':text[:m.start()].count('\n')+1,
                'body':body,'nature':'official_reference_not_incident_or_dialogue','failure_targets':['invalid_waf_configuration','waf_detection_vs_block'],
                'training_admitted':False})
    nist_path='nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json'
    catalog=json.loads((root/'raw/nist_controls'/nist_path).read_text())['catalog']
    def controls(xs):
        for c in xs:
            yield c
            yield from controls(c.get('controls',[]))
    for group in catalog['groups']:
        if group['id'] not in ('ac','au','ca','cm','cp','ir','ra','si'):continue
        for c in controls(group['controls']):
            if any(p.get('name')=='status' and p.get('value')=='withdrawn' for p in c.get('props',[])):continue
            knowledge.append({'source':'nist_controls','source_path':nist_path,
                'source_sha256':files[('nist_controls',nist_path)]['sha256'],'control_id':c['id'],'family':group['id'],
                'control':c,'nature':'official_control_not_project_approval_protocol',
                'failure_targets':['approval_candidate_integrity','evidence_vs_inference','change_verification'],
                'training_admitted':False})
    counter=root/'raw/cisa_counter'
    for file in sorted((counter/'countermeasures').glob('*.md')):
        path=str(file.relative_to(counter));body=file.read_text();item=files[('cisa_counter',path)]
        knowledge.append({'source':'cisa_counter','source_path':path,'source_sha256':item['sha256'],
            'source_url':item['url'],'source_commit':item['commit'],'body':body,
            'nature':'official_response_guidance_not_incident_or_execution_authority',
            'failure_targets':['containment_planning','side_effects','investigation','recovery'],
            'section_headings':re.findall(r'^## (.+)$',body,re.M),
            'training_admitted':False})
    knowledge_file=derived/'knowledge-records.jsonl';knowledge_file.write_text(''.join(canonical(x)+'\n' for x in knowledge))
    summary={}
    for source in ('crs','wazuh'):
        records_=[r for r in rows if r['source']==source];good=[r for r in records_ if not r['reasons']]
        summary[source]={'provider_records':len(records_),'static_linked':len(good),'quarantined':len(records_)-len(good),
                         'reason_counts':dict(Counter(reason for r in records_ for reason in set(r['reasons']))),
                         'provisional_partitions':dict(Counter(r['provisional_partition'] for r in good)),
                         'split_groups':len({r['split_group'] for r in good})}
    result={'at_kst':now(),'stage':'static_linkage_review_not_training_admission','sources':summary,
            'knowledge_units':dict(Counter(r['source'] for r in knowledge)),
            'xml_parse_errors':xml_errors,'empty_or_nonmapping_yaml':empty_yaml,
            'output_sha256':{records.name:sha(records.read_bytes()),knowledge_file.name:sha(knowledge_file.read_bytes())},
            'limitations':['No engine replay or model tokenization','Provisional family partitions need cross-history/semantic overlap review',
                           'No institutional certification of generated dialogues','No new SFT admission or GPU training'],
            'training_admitted':0,'raw_cases_are_independent_incidents':False}
    write(derived/'review-summary.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
    p.add_argument('--history-root',type=Path)
    a=p.parse_args()
    result=review(a.root)
    if a.history_root:
        hist=history_review(a.root,a.history_root)
        result['history']={k:v for k,v in hist.items() if k not in ('files','matched_record_ids')}
        result['history']['matched_records']=len(hist['matched_record_ids'])
    print(json.dumps(result,ensure_ascii=False))
