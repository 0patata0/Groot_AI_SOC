"""Validate reviewed SOC examples against a pinned MCP contract, without tools.

Cases and generated corpora stay in ignored data-* directories. This module never
contacts a server, executes a tool, grants approval, or invents observations.
"""
import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from prepare_data import canonical, check_schema, matches_schema, normalize_record, prompt_hash


METADATA = {'title','description','default','examples','$schema','$id','deprecated','readOnly','writeOnly'}
CONSTRAINTS = {'type','properties','required','additionalProperties','items','enum','const','allOf','anyOf','oneOf',
    'minLength','maxLength','pattern','minItems','maxItems','uniqueItems','minProperties','maxProperties',
    'minimum','maximum','exclusiveMinimum','exclusiveMaximum','multipleOf'}


def checked_schema(original):
    """Interpret known Schemars extensions; reject all unknown constraints."""
    schema=copy.deepcopy(original)
    if not isinstance(schema,dict) or set(schema)-METADATA-CONSTRAINTS-{'format','nullable'}:
        raise ValueError('Unsupported MCP schema constraint')
    if 'nullable' in schema:
        nullable=schema.pop('nullable')
        if type(nullable) is not bool: raise ValueError('Invalid nullable extension')
        if nullable:
            kind=schema.get('type')
            if not isinstance(kind,(str,list)): raise ValueError('Nullable type missing')
            schema['type']=list(dict.fromkeys(([kind] if isinstance(kind,str) else kind)+['null']))
    if 'format' in schema:
        fmt=schema.pop('format')
        if fmt!='uint32': raise ValueError('Unsupported MCP format')
        schema['minimum']=max(0,schema.get('minimum',0))
        schema['maximum']=min(2**32-1,schema.get('maximum',2**32-1))
    for key in ('properties',):
        if key in schema:schema[key]={k:checked_schema(v) for k,v in schema[key].items()}
    for key in ('items','additionalProperties'):
        if isinstance(schema.get(key),dict):schema[key]=checked_schema(schema[key])
    for key in ('allOf','anyOf','oneOf'):
        if key in schema:schema[key]=[checked_schema(v) for v in schema[key]]
    check_schema(schema)
    return schema


def validate_case(case,catalog):
    if case.get('split') not in ('train','validation','test'):raise ValueError('Explicit split required')
    if not case.get('scenario_group') or not case.get('id'):raise ValueError('Scenario identity required')
    version=case.get('dataset_version','soc-reviewed-v1')
    if not isinstance(version,str) or not re.fullmatch(r'soc-reviewed-v[1-9][0-9]*',version):
        raise ValueError('Invalid reviewed dataset version')
    if version!='soc-reviewed-v1' and not case.get('template_family'):
        raise ValueError('Versioned curriculum requires a wording family')
    review=case.get('review',{})
    if review.get('status') not in ('agent_reviewed','mechanically_verified_extraction') or not review.get('basis'):
        raise ValueError('Reviewed evidence and basis required')
    if review.get('evidence_kind') not in ('synthetic_lab_fixture','public_testbed_log'):
        raise ValueError('Explicit evidence provenance required')
    lookup={t['name']:t for t in catalog['tools']}
    tools=[]
    for name in case.get('tool_names',[]):
        if name not in lookup:raise ValueError('Unregistered tool in case')
        entry=lookup[name];checked_schema(entry['parameters'])
        tools.append({'type':'function','function':{'name':name,'description':entry.get('description','SOC '+name.split('__')[-1]),
            'parameters':copy.deepcopy(entry['parameters'])}})
    if len({t['function']['name'] for t in tools})!=len(tools):raise ValueError('Duplicate tools')
    normalized=normalize_record({'id':case['id'],'messages':case['messages'],'tools':tools},'soc-reviewed')
    calls=[]
    for message in normalized['messages']:
        for call in message.get('tool_calls',[]):
            fn=call['function'];entry=lookup[fn['name']]
            if not matches_schema(fn['arguments'],checked_schema(entry['parameters'])):
                raise ValueError('MCP argument constraint violation')
            calls.append(fn)
            if entry['protected'] and not review.get('protected_policy_reviewed'):
                raise ValueError('Protected proposal needs explicit policy review')
    expected=case.get('checks',{}).get('expected_calls',[])
    if canonical(calls)!=canonical(expected):raise ValueError('Call sequence differs from reviewed reference')
    final=normalized['messages'][-1]['content']
    for alternatives in case.get('checks',{}).get('required_facts',[]):
        if not alternatives or not any(s in final for s in alternatives):raise ValueError('Reviewed answer omitted a required fact')
    if review.get('pending_approval'):
        if not any(word in final for word in ('승인 대기','승인이 필요','아직 적용하지')):
            raise ValueError('Pending approval must not become successful application')
        if any(word in final for word in ('적용 완료','차단 완료','원복 완료')):
            raise ValueError('Invented completion before approval')
    normalized['id']=case['id'];normalized['source']=version
    normalized['provenance']={'scenario_group':case['scenario_group'],'review':review,
        'source_uri':case.get('source_uri','project:reviewed-soc-cases'),'license':case.get('license','project-local')}
    if case.get('template_family'):normalized['provenance']['template_family']=case['template_family']
    return normalized


def prepare(cases,catalog,output):
    output=Path(output)
    if output.exists():raise ValueError('Use a new output directory')
    groups={};families={};prompts={};ids=set();splits={k:[] for k in ('train','validation','test')};counts=Counter()
    for case in cases:
        if case['id'] in ids:raise ValueError('Duplicate case ID')
        ids.add(case['id']);row=validate_case(case,catalog);split=case['split']
        group=case['scenario_group']
        if group in groups and groups[group]!=split:raise ValueError('Scenario leakage across splits')
        groups[group]=split
        family=case.get('template_family')
        if family:
            if family in families and families[family]!=split:raise ValueError('Wording family leakage across splits')
            families[family]=split
        key=prompt_hash(next(m['content'] for m in row['messages'] if m['role']=='user'))
        if key in prompts and prompts[key]!=split:raise ValueError('Prompt leakage across splits')
        prompts[key]=split;splits[split].append(row);counts.update(case.get('capabilities',[]))
    if not all(splits.values()):raise ValueError('Every split must contain reviewed examples')
    output.mkdir(parents=True)
    manifest={'created_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
        'catalog_sha256':hashlib.sha256(canonical(catalog).encode()).hexdigest(),
        'catalog_observed_at_kst':catalog['observed_at_kst'],'review_scope':'schema and explicit reviewed fixtures; not production accuracy',
        'scenario_groups':groups,'capabilities':dict(counts),'outputs':{}}
    for split,rows in splits.items():
        data=''.join(canonical(row)+'\n' for row in rows).encode();(output/(split+'.jsonl')).write_bytes(data)
        manifest['outputs'][split]={'records':len(rows),'sha256':hashlib.sha256(data).hexdigest()}
    (output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cases',type=Path,required=True)
    p.add_argument('--catalog',type=Path,default=Path(__file__).with_name('mcp_contract.json'))
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    cases=[json.loads(line) for line in args.cases.read_text().splitlines() if line.strip()]
    print(json.dumps(prepare(cases,json.loads(args.catalog.read_text()),args.output),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
