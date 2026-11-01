"""Freeze a locally reviewed mixture, then admit whole dialogues using DGX token receipts.

This utility never starts training. Long conversations are excluded. A separately
identified tool-selection-only example may be admitted for an oversized live
read; it is never counted as a full investigation trajectory.
"""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import re
import shutil
from datetime import datetime
from zoneinfo import ZoneInfo

from audit_tools import audit_rows
from prepare_operator_sources import ROOT, canonical, sha, rows, dump

SECRET_KEYS = {'password','passwd','secretaccesskey','sessiontoken','accesstoken','refreshtoken',
               'clientsecret','authorization','privatekey','apikey','keymaterial','cookie','setcookie'}


def explicit_secret(value):
    if isinstance(value, dict):
        for key, child in value.items():
            compact = re.sub('[^a-z]', '', key.casefold())
            if compact in SECRET_KEYS and child and not (isinstance(child,str) and ('REDACTED' in child or child.startswith('${'))):
                return True
            if explicit_secret(child):return True
    elif isinstance(value,list):
        return any(explicit_secret(x) for x in value)
    elif isinstance(value,str):
        if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bAKIA[A-Z0-9]{16}\b',value):
            return True
        if value.lstrip().startswith(('{','[')):
            try:return explicit_secret(json.loads(value))
            except json.JSONDecodeError:pass
    return False


def private_observations(row):
    # Inspect structured user/tool payloads; source commands are never executed.
    for message in row['messages']:
        if message['role'] not in ('user','tool'):continue
        text = message.get('content') or ''
        if explicit_secret(text):return True
        for line in text.splitlines():
            if explicit_secret(line):return True
    return False


def input_identity(row):
    return sha(canonical([m for m in row['messages'] if m['role'] not in ('assistant','system')]).encode())


def verify_module(path):
    manifest = json.loads((path/'composition.json').read_text())
    for name, digest in manifest['files'].items():
        file = path/name
        if file.is_symlink() or not file.resolve().is_relative_to(path.resolve()) or sha(file.read_bytes()) != digest:
            raise ValueError('Composed module changed: '+name)
    return manifest


def compose(source, mcp, output):
    source, mcp, output = Path(source), Path(mcp), Path(output)
    if output.exists() or not output.name.startswith('data-'):raise ValueError('Use a new data-* directory')
    source_report, mcp_report = verify_module(source), verify_module(mcp)
    training = rows(source/'train.candidates.jsonl')+rows(mcp/'candidates.jsonl')
    validation, test = rows(source/'validation.jsonl'), rows(source/'test.jsonl')
    eval_inputs = {input_identity(r) for r in validation+test}
    eval_ids = {r['id'] for r in validation+test}
    eligible, held, seen = [], [], set()
    for row in training:
        if row['id'] in seen or row['id'] in eval_ids:raise ValueError('Duplicate or evaluation ID')
        seen.add(row['id'])
        if input_identity(row) in eval_inputs:
            held.append({'id':row['id'],'reason':'exact_evaluation_input_overlap'});continue
        if private_observations(row):
            held.append({'id':row['id'],'reason':'explicit_credential_pattern_or_field'});continue
        eligible.append(row)
    catalog = json.loads((ROOT/'mcp_contract.20261101.json').read_text())
    audit = audit_rows(eligible,catalog)
    if audit['counts'].get('calls',0) != audit['counts'].get('schema_valid_calls',0):
        raise ValueError('Unvalidated tool call in mixture')
    fallbacks = []
    for row in eligible:
        if row['source'] != 'project_live_mcp':continue
        fallback = copy.deepcopy(row)
        fallback['id'] += '-initial-call'
        fallback['messages'] = fallback['messages'][:3]
        assert fallback['messages'][-1]['role']=='assistant' and fallback['messages'][-1].get('tool_calls')
        fallback['provenance'].update(trajectory_scope='initial_tool_selection_only',parent_dialogue=row['id'])
        fallbacks.append(fallback)
    output.mkdir()
    dump(output/'train.candidates.jsonl',eligible)
    dump(output/'fallback.candidates.jsonl',fallbacks)
    dump(output/'held-before-token.jsonl',held)
    for split in ('validation','test'):shutil.copyfile(source/(split+'.jsonl'),output/(split+'.jsonl'))
    shutil.copytree(source/'licenses',output/'licenses')
    shutil.copyfile(source/'new-source-lineage.jsonl',output/'new-source-lineage.jsonl')
    shutil.copyfile(mcp/'execution-evidence.jsonl',output/'execution-evidence.jsonl')
    shutil.copyfile(ROOT/'mcp_contract.20261101.json',output/'mcp-contract.json')
    inputs = [{'split':split,'row':row} for split,rs in [('train',eligible),('fallback',fallbacks),('validation',validation),('test',test)] for row in rs]
    dump(output/'token-input.jsonl',inputs)
    report={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'status':'waiting_exact_token_receipt',
            'source_module_sha256':sha((source/'composition.json').read_bytes()),
            'mcp_module_sha256':sha((mcp/'composition.json').read_bytes()),
            'source_counts':dict(Counter(r['source']for r in eligible)),
            'candidate_rows':len(eligible),'separate_fallback_candidates':len(fallbacks),
            'held_before_token':held,'validation_rows':len(validation),'test_rows':len(test),
            'exact_evaluation_input_overlap':sum(r['reason']=='exact_evaluation_input_overlap'for r in held),
            'schema_audit':audit,'cleansing_location':'local','ready_for_gpu_training':False,
            'token_input_sha256':sha((output/'token-input.jsonl').read_bytes()),
            'files':{str(p.relative_to(output)):sha(p.read_bytes())for p in output.rglob('*')if p.is_file()}}
    (output/'composition.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


def admit(directory, token_receipt):
    directory, token_receipt = Path(directory), Path(token_receipt)
    composition = verify_module(directory)
    if (directory/'admission.json').exists():raise ValueError('Admission already frozen')
    result = json.loads(token_receipt.read_text())
    if result['input_sha256'] != composition['token_input_sha256'] or result['max_length'] != 4096 or result['truncation']:
        raise ValueError('Token receipt does not bind exact input/length')
    if result['weights_loaded'] or result['gpu_training_started']:raise ValueError('Unexpected token probe side effects')
    # Compare tokenizer hashes with the earlier pinned-base CPU token receipt.
    previous=json.loads((ROOT/'data-joint-sft-20261101-r3/token-review.json').read_text())
    if result['artifacts'] != previous['artifacts']:raise ValueError('Pinned tokenizer artifacts differ')
    expected = {(r['split'],r['row']['id']) for r in rows(directory/'token-input.jsonl')}
    actual = {(r['split'],r['id']) for r in result['records']}
    if expected != actual or len(actual)!=len(result['records']):raise ValueError('Missing/duplicated token results')
    for record in result['records']:
        if record['reason'] is None and (type(record['tokens']) is not int or not 0 < record['tokens'] <= 4096):
            raise ValueError('Invalid admitted token length')
    tokens = {(r['split'],r['id']):r for r in result['records']}
    admitted, held = [], []
    fallback = {r['provenance']['parent_dialogue']:r for r in rows(directory/'fallback.candidates.jsonl')}
    for row in rows(directory/'train.candidates.jsonl'):
        record = tokens[('train',row['id'])]
        if record['reason'] is None:
            admitted.append(row);continue
        if record['reason'] != 'over_max_length':raise ValueError('Encoding alignment/schema failure: '+row['id'])
        held.append({'id':row['id'],'reason':record['reason']})
        candidate=fallback.get(row['id'])
        if candidate and tokens[('fallback',candidate['id'])]['reason'] is None:
            admitted.append(candidate)
    for split in ('validation','test'):
        if any(tokens[(split,r['id'])]['reason'] for r in rows(directory/(split+'.jsonl'))):
            raise ValueError('Frozen evaluation no longer fits')
    dump(directory/'train.jsonl',admitted)
    dump(directory/'held-token.jsonl',held)
    admitted_tokens=[tokens[('fallback'if r['id'].endswith('-initial-call')else'train',r['id'])]['tokens']for r in admitted]
    report={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
            'status':'source_and_token_verified_waiting_final_review_and_gpu_smoke',
            'train_rows':len(admitted),'validation_rows':composition['validation_rows'],'test_rows':composition['test_rows'],
            'source_counts':dict(Counter(r['source']for r in admitted)),
            'full_mcp_dialogues':sum(any(m['role']=='tool'for m in r['messages'])for r in admitted),
            'initial_tool_selection_only':sum(r['id'].endswith('-initial-call')for r in admitted),
            'max_tokens':max(admitted_tokens),'total_tokens':sum(admitted_tokens),'truncation':False,
            'token_receipt_sha256':sha(token_receipt.read_bytes()),'held_long_dialogues':len(held),
            'ready_for_gpu_training':False,'new_gpu_training_started':False,
            'files':{name:sha((directory/name).read_bytes())for name in ('train.jsonl','validation.jsonl','test.jsonl','held-token.jsonl')}}
    (directory/'admission.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path)
    parser.add_argument('--mcp',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--token-receipt',type=Path)
    args=parser.parse_args()
    result=admit(args.output,args.token_receipt)if args.token_receipt else compose(args.source,args.mcp,args.output)
    print(json.dumps(result,ensure_ascii=False,indent=2))
