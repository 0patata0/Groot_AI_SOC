"""Convert the pinned ToolACE subset conservatively; no model or tool execution.

API aliases are a reversible transport mapping, never operational MCP aliases.
Unparseable calls, unknown constraints and ambiguous responses are rejected.
"""
import argparse
import ast
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from prepare_data import Reject,canonical,normalize_record,prompt_hash,split_for_group,eval_prompt_hashes
from soc_dataset import checked_schema

PINNED_SHA='ba12c083fca7e8da48c67ad5b895e495447da7c66e39a2e19742c082e6cb537e'
MARKER='Here is a list of functions in JSON format that you can invoke:'
ALIASES={'dict':'object','str':'string','int':'integer','float':'number','bool':'boolean','list':'array'}

def schema(value):
    value=copy.deepcopy(value)
    if not isinstance(value,dict):raise Reject('schema_not_object')
    if isinstance(value.get('type'),str):value['type']=ALIASES.get(value['type'],value['type'])
    if 'properties' in value:
        if not isinstance(value['properties'],dict):raise Reject('invalid_properties')
        value['properties']={k:schema(v) for k,v in value['properties'].items()}
    for key in ('items','additionalProperties'):
        if isinstance(value.get(key),dict):value[key]=schema(value[key])
    for key in ('allOf','anyOf','oneOf'):
        if key in value:value[key]=[schema(v) for v in value[key]]
    try:return checked_schema(value)
    except (ValueError,TypeError,AttributeError) as exc:raise Reject('unsupported_schema') from exc

def alias(name):return 'toolace_'+hashlib.sha256(name.encode()).hexdigest()[:20]

def outside_string_aliases(text,names):
    result=[];i=0;quote=None;escape=False;ordered=sorted(names,key=len,reverse=True)
    while i<len(text):
        char=text[i]
        if quote:
            result.append(char)
            if escape:escape=False
            elif char=='\\':escape=True
            elif char==quote:quote=None
            i+=1;continue
        if char in ['"',"'"]:quote=char;result.append(char);i+=1;continue
        matched=next((n for n in ordered if text.startswith(n,i) and re.match(r'\s*\(',text[i+len(n):]) and (i==0 or text[i-1] in '[, \n\t')),None)
        if matched:result.append(names[matched]);i+=len(matched)
        else:result.append(char);i+=1
    return ''.join(result)

def parse_calls(text,names):
    if len(text)>60000:raise Reject('call_text_too_long')
    try:tree=ast.parse(outside_string_aliases(text,names),mode='eval')
    except (SyntaxError,ValueError,RecursionError):raise Reject('unparseable_call') from None
    nodes=tree.body.elts if isinstance(tree.body,ast.List) else []
    if not nodes:raise Reject('empty_or_nonlist_call')
    calls=[]
    for node in nodes:
        if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Name) or node.func.id not in names.values() or node.args:raise Reject('unsupported_call_expression')
        args={}
        for item in node.keywords:
            if item.arg is None or item.arg in args:raise Reject('ambiguous_call_arguments')
            try:args[item.arg]=ast.literal_eval(item.value)
            except (ValueError,TypeError,RecursionError):raise Reject('nonliteral_argument') from None
        calls.append({'function':{'name':node.func.id,'arguments':args}})
    return calls

def convert(row,index):
    raw_system=row.get('system','')
    if raw_system.count(MARKER)!=1:raise Reject('tool_marker_missing_or_ambiguous')
    preamble,raw_tools=raw_system.split(MARKER,1)
    try:tools,_=json.JSONDecoder().raw_decode(raw_tools.lstrip())
    except (ValueError,TypeError):raise Reject('invalid_tools_json') from None
    if not isinstance(tools,list) or not tools:raise Reject('no_tools')
    names={};normalized=[]
    for tool in tools:
        name=tool.get('name')
        if not isinstance(name,str) or not name.strip() or name in names:raise Reject('duplicate_or_invalid_tool')
        names[name]=alias(name);normalized.append({'type':'function','function':{'name':names[name],'description':tool.get('description',''),'parameters':schema(tool['parameters'])}})
    messages=[{'role':'system','content':preamble.strip()}];pending=[]
    for turn in row.get('conversations',[]):
        role=turn.get('from');value=turn.get('value')
        if not isinstance(value,str):raise Reject('nontext_turn')
        if role=='assistant' and value.strip().startswith('[') and '(' in value:
            calls=parse_calls(value.strip(),names)
            if pending:raise Reject('missing_tool_result')
            for n,call in enumerate(calls):call['id']=f'source_{index}_{len(messages)}_{n}'
            pending=[(c['function']['name'],c['id']) for c in calls];messages.append({'role':'assistant','content':'','tool_calls':calls})
        elif role=='tool':
            try:results=json.loads(value)
            except ValueError:raise Reject('nonjson_tool_result') from None
            if not isinstance(results,list) or not results:raise Reject('nonlist_tool_result')
            for response in results:
                if not isinstance(response,dict) or response.get('name') not in names or 'results' not in response:raise Reject('unidentified_tool_result')
                name=names[response['name']];matches=[x for x in pending if x[0]==name]
                if len(matches)!=1:raise Reject('ambiguous_tool_result')
                pair=matches[0];pending.remove(pair);messages.append({'role':'tool','name':name,'tool_call_id':pair[1],'content':canonical(response['results'])})
        elif role in ('user','assistant'):
            if pending:raise Reject('missing_tool_result')
            if role=='assistant' and value.strip() in ['[]','None','null']:raise Reject('uninformative_no_action')
            messages.append({'role':role,'content':value})
        else:raise Reject('unknown_role')
    obj={'messages':messages,'tools':normalized,'id':index};result=normalize_record(obj,'toolace',index)
    result['provenance']={'source_uri':'https://huggingface.co/datasets/Team-ACE/ToolACE','license':'Apache-2.0','source_file_sha256':PINNED_SHA,'source_array_index_1based':index,'source_record_sha256':hashlib.sha256(canonical(row).encode()).hexdigest(),'api_name_map':names,'evidence_kind':'external_synthetic_tool_dialogue','review_scope':'structural/argument/response-link checks only; no independent semantic expert review','tool_execution':'source fixture only; not executed here'}
    return result

def blocked_prompts(root):
    paths=sorted((root/'datasets/processed/eval').glob('*.jsonl'))+[root/'datasets/raw/sevenllm/test.jsonl']
    paths+=list((root/'finetuning').glob('data*/test.jsonl'))
    quality=root/'대화기록/검증/2026-10-28-quality/cases.jsonl'
    if quality.exists():paths.append(quality)
    blocked=set();sources={}
    for p in paths:
        data=p.read_bytes();sources[str(p.relative_to(root))]=hashlib.sha256(data).hexdigest()
        for line in data.splitlines():blocked.update(eval_prompt_hashes(json.loads(line)))
    return blocked,sources

def prepare(root,output):
    if output.exists():raise ValueError('Use a new immutable output directory')
    p=root/'datasets/raw/toolace/data.json';raw=p.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PINNED_SHA:raise ValueError('ToolACE source hash mismatch')
    rows=json.loads(raw);blocked,exclusions=blocked_prompts(root);rejected=Counter();selected={};groups={}
    for i,row in enumerate(rows,1):
        try:
            result=convert(row,i);question=next(x['content'] for x in result['messages'] if x['role']=='user');key=prompt_hash(question)
            if key in blocked:raise Reject('evaluation_prompt_overlap')
            if len(canonical(result))>60000:raise Reject('over_character_limit')
            content=canonical({'messages':result['messages'],'tools':result['tools']});digest=hashlib.sha256(content.encode()).hexdigest()
            if digest in selected:raise Reject('duplicate_conversation')
            shape=prompt_hash(re.sub(r'\d+','<n>',question.lower()));group=groups.setdefault(key,split_for_group(shape,20261029,0.1,0.1));selected[digest]=(group,result)
        except (Reject,KeyError,TypeError,RecursionError) as exc:rejected[str(exc) if isinstance(exc,Reject) else 'unsupported_record_shape']+=1
    if not selected:raise ValueError('No eligible ToolACE examples')
    output.mkdir(parents=True);outputs={}
    for split in ('train','validation','test'):
        kept=[r for _,(s,r) in sorted(selected.items()) if s==split];data=''.join(canonical(r)+'\n' for r in kept).encode();(output/(split+'.jsonl')).write_bytes(data);outputs[split]={'records':len(kept),'sha256':hashlib.sha256(data).hexdigest()}
    manifest={'created_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'source_file_sha256':PINNED_SHA,'input_rows':len(rows),'accepted_rows':len(selected),'rejected':dict(rejected),'outputs':outputs,'evaluation_exclusion_inputs':exclusions,'blocked_prompt_groups':len(blocked),'aliases':'reversible namespace mapping only; never mapped to operational MCP names','grouping':'first question, case-normalized and numeric-shape grouped; semantic duplication not fully established','tokenization':'not yet measured; do not interpret character cap as token budget','semantic_accuracy':'not independently expert reviewed','source':{'uri':'https://huggingface.co/datasets/Team-ACE/ToolACE','license':'Apache-2.0'}};(output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');return manifest

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(prepare(a.root,a.output),ensure_ascii=False))
if __name__=='__main__':main()
