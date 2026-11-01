"""Clean complete recording files into evidence blocks, never fabricated answers.

Blocks are retrieval/evidence candidates, not independently labelled incidents or
SFT conversations. Whole source cases/shared files remain in one partition.
"""
import argparse
from collections import Counter, defaultdict
import io
import json
from pathlib import Path
import re
import stat
import zipfile
from collect_defensive_sources import now, sha, safe_path, write

MAX_MEMBER = 128 * 1024**2
MAX_EXPANDED_ARCHIVE = 256 * 1024**2
MAX_BLOCK = 12000
SECRET = re.compile(r'(?i)^(password|passwd|access_token|refresh_token|client_secret|authorization|cookie|set-cookie|private_key|api_key)$')
LABELS = {'attacktechnique','attacktechniques','subtechniques','techniques','label','ground_truth','groundtruth','incidentgrade','classification'}
REVIEWED_TRANSFER_SOURCES = {'splunk_attack'}


def canonical(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def sanitize(x, counts):
    if isinstance(x,dict):
        out={}
        for k,v in x.items():
            if SECRET.fullmatch(k): out[k]='[REDACTED]';counts['secret_fields']+=1
            elif k.lower() in LABELS: counts['annotation_fields']+=1
            else:out[k]=sanitize(v,counts)
        return out
    if isinstance(x,list):return [sanitize(v,counts)for v in x]
    if isinstance(x,str):
        x,n=re.subn(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','[REDACTED PRIVATE KEY]',x)
        counts['secret_text_spans']+=n
        x,n=re.subn(r'(?i)\b(password|passwd|access_token|refresh_token|client_secret|api_key)\s*[=:]\s*(["\']?)[^\s,;"\'<>]+\2',r'\1=[REDACTED]',x)
        counts['secret_text_spans']+=n
    return x


def blocks(data, counts):
    text=data.decode('utf-8-sig')
    if '\x00' in text: raise ValueError('binary_nul')
    if text.lstrip().startswith(('{','[')):
        try:
            value=json.loads(text); rows=value if isinstance(value,list) else [value]
            located=[({'json_index':i},v) for i,v in enumerate(rows)]
        except json.JSONDecodeError:
            located=[]
            for n,line in enumerate(text.splitlines(),1):
                if line.strip():located.append(({'line':n},json.loads(line)))
        output=[]
        for loc,value in located:
            value=sanitize(value,counts)
            if len(canonical(value).encode())>MAX_BLOCK: raise ValueError('whole_record_exceeds_block_bound')
            output.append({'locator':loc,'format':'json_record','observation':value})
        return output
    # Do not call XML fragments or multiline text an event. Every complete source
    # line remains in a bounded, consecutive text block; overlong files are held.
    output=[];chunk=[];size=0;first=1
    for n,line in enumerate(text.splitlines(keepends=True),1):
        line=sanitize(line,counts);length=len(line.encode())
        if length>MAX_BLOCK:raise ValueError('whole_line_exceeds_block_bound')
        if chunk and size+length>MAX_BLOCK:
            output.append({'locator':{'line_start':first,'line_end':n-1},'format':'text_block_not_event','observation':''.join(chunk)})
            chunk=[];size=0;first=n
        chunk.append(line);size+=length
    if chunk:output.append({'locator':{'line_start':first,'line_end':n},'format':'text_block_not_event','observation':''.join(chunk)})
    return output


def members(path):
    if path.suffix!='.zip':return [(None,path.read_bytes())]
    with zipfile.ZipFile(path)as z:
        infos=z.infolist()
        if sum(i.file_size for i in infos)>MAX_EXPANDED_ARCHIVE:raise ValueError('archive_expansion_bound')
        seen=set();out=[]
        for i in infos:
            if i.is_dir():continue
            safe_path(i.filename)
            if i.filename in seen:raise ValueError('duplicate_zip_member')
            seen.add(i.filename)
            if i.flag_bits&1 or stat.S_ISLNK(i.external_attr>>16):raise ValueError('encrypted_or_link_member')
            if i.file_size>MAX_MEMBER:raise ValueError('member_size_bound')
            if not i.filename.endswith(('.json','.jsonl','.log','.csv','.txt')):continue
            data=z.read(i) # zipfile verifies CRC32; no archive members executed.
            if len(data)!=i.file_size:raise ValueError('zip_size_mismatch')
            out.append((i.filename,data))
        if not out:raise ValueError('no_supported_text_members')
        return out


def prepare(root,output):
    root=Path(root);output=Path(output);output.mkdir(parents=True,exist_ok=False)
    plan=json.loads((root/'event-plan.json').read_text());acq=json.loads((root/'event-acquisition.json').read_text())
    cases={c['id']:c for c in plan['cases']if c['source']in REVIEWED_TRANSFER_SOURCES};parent={k:k for k in cases}
    eligible_files=[x for x in acq['files']if x['source']in REVIEWED_TRANSFER_SOURCES]
    def find(k):
        while parent[k]!=k:parent[k]=parent[parent[k]];k=parent[k]
        return k
    def join(ids):
        roots=sorted({find(k)for k in ids});base=roots[0]
        for k in roots[1:]:parent[k]=base
    providers=defaultdict(list);byfile=defaultdict(list)
    for c in cases.values():providers[c['provider_id']].append(c['id'])
    for ids in providers.values():join(ids)
    for item in eligible_files:byfile[item['sha256']].extend(item['case_ids'])
    for ids in byfile.values():join(ids)
    groups={k:find(k)for k in cases}
    partition={g:'eval'if int(sha(('soc-event-split-v1:'+g).encode())[:8],16)%5==0 else'train' for g in set(groups.values())}
    stats=Counter();held=[];draft=output/'draft.jsonl';seen=defaultdict(set);file_reports=[]
    with draft.open('w')as out:
        for index,item in enumerate(eligible_files):
            path=root/item['stored_path'];data=path.read_bytes()
            if sha(data)!=item['sha256']or len(data)!=item['bytes']:raise ValueError('Acquired evidence changed')
            group=groups[item['case_ids'][0]]
            if any(groups[c]!=group for c in item['case_ids']):raise ValueError('Source file split')
            split=partition[group];temp_counts=Counter();parsed=[]
            try:
                for member,b in members(path):
                    member_hash=sha(b)
                    for block in blocks(b,temp_counts):
                        fingerprint=sha(canonical([block['format'],block['observation']]).encode())
                        row={'id':sha(canonical([item['source'],item['path'],member,block['locator']]).encode()),
                             'source':item['source'],'source_path':item['path'],'source_sha256':item['sha256'],
                             'member':member,'member_sha256':member_hash,'case_ids':item['case_ids'],
                             'split_group':group,'partition':split,'input_sha256':fingerprint,
                             **block,'training_admitted':False,'target':None}
                        parsed.append(row)
            except (ValueError,UnicodeError,zipfile.BadZipFile,RuntimeError)as e:
                held.append({'source':item['source'],'path':item['path'],'sha256':item['sha256'],'case_ids':item['case_ids'],'reason':str(e)[:120]});continue
            stats.update(temp_counts)
            for row in parsed:out.write(canonical(row)+'\n');seen[row['input_sha256']].add(split)
            file_reports.append({'source':item['source'],'path':item['path'],'sha256':item['sha256'],'blocks':len(parsed),'partition':split,'case_ids':item['case_ids']})
            if index%100==0:print(json.dumps({'phase':'clean','files':index,'held':len(held)}),flush=True)
    outputs={s:(output/('observations-'+s+'.jsonl')).open('w')for s in ('train','eval')}
    kept=set();counts=Counter();case_blocks=Counter();formats=Counter();excluded=Counter()
    stream=draft.open()
    try:
        for line in stream:
            row=json.loads(line);h=row['input_sha256']
            if len(seen[h])>1:excluded['cross_partition_duplicate_block']+=1;continue
            if h in kept:excluded['duplicate_block']+=1;continue
            kept.add(h);outputs[row['partition']].write(line);counts[row['partition']]+=1;formats[row['format']]+=1
            case_blocks.update(row['case_ids'])
    finally:
        stream.close()
        for f in outputs.values():f.close()
    draft.unlink() # This task's intermediate file only; source evidence preserved.
    acquired={ (x['source'],x['path'])for x in acq['files']};cleaned={(x['source'],x['path'])for x in file_reports}
    for c in cases.values():
        c['partition']=partition[groups[c['id']]];c['split_group']=groups[c['id']];c['retained_blocks']=case_blocks[c['id']]
        c['acquired_files']=sum((c['source'],p)in acquired for p in c['files'])
        c['cleaned_files']=sum((c['source'],p)in cleaned for p in c['files'])
        c['all_linked_files_cleaned']=bool(c['files'])and c['cleaned_files']==len(c['files'])
    (output/'case-lineage.jsonl').write_text(''.join(canonical(c)+'\n'for c in cases.values()))
    write(output/'file-review.json',{'cleaned':file_reports,'held':held,'source_plan_held':plan['held'],'download_errors':acq['errors']})
    for key in sorted(REVIEWED_TRANSFER_SOURCES):
        (output/(key+'-LICENSE.txt')).write_bytes((root/'raw'/key/'LICENSE').read_bytes())
    summary={'at_kst':now(),'source_cases':len(cases),'unique_provider_ids':len(providers),'known_file_identity_components':len(set(groups.values())),
             'reviewed_transfer_sources':sorted(REVIEWED_TRANSFER_SOURCES),
             'rights_held_files':len(acq['files'])-len(eligible_files),
             'rights_hold':'OTRF LICENSE/header MIT but README footer GPL-3.0; exclude OTRF data from transfer pending clarification.',
             'acquired_files':len(acq['files']),'acquired_bytes':acq['bytes'],'cleaned_files':len(file_reports),'held_files':len(held),
             'observation_blocks':dict(counts),'formats':dict(formats),'redactions':dict(stats),'duplicate_exclusions':dict(excluded),
             'cases_with_retained_blocks':sum(bool(c['retained_blocks'])for c in cases.values()),
             'complete_linked_cases':sum(c['all_linked_files_cleaned']for c in cases.values()),
             'held_reasons':dict(Counter(x['reason']for x in held)),
             'cross_partition_exact_observation_overlap':0,'training_admitted':0,'ready_for_gpu_training':False,
             'limitations':['Observation blocks are not independent incidents or supervised answers.',
                 'Scenario attack descriptions do not label every event as malicious; no invented benign or success targets.',
                 'Only explicit sensitive fields/text patterns are redacted; final privacy and semantic review remain.',
                 'Splits join provider IDs/shared acquired files; semantic and historical-family overlap remain to review.',
                 'All logs are untrusted data, never executable tool instructions.'],
             'files':{p.name:sha(p.read_bytes())for p in output.iterdir()if p.is_file()}}
    write(output/'MANIFEST.json',summary);return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=prepare(a.root,a.output);print(json.dumps({k:v for k,v in r.items()if k!='files'},ensure_ascii=False))
