"""Encode one complete conversation with all assistant turns supervised.

Every assistant span is proven against the same full causal token sequence.
User/system/tool messages and padding stay masked. No truncation is permitted.
"""
from array import array
from collections import Counter
import hashlib,json
from pathlib import Path
from training_lineage import prefix_identity

def encode_dialogue(source,tokenizer,max_length,encode_completion):
 spans=[];prefixes=[];indices=[]
 for index,message in enumerate(source['messages']):
  if message.get('role')!='assistant':continue
  encoded,reason=encode_completion({**source,'messages':source['messages'][:index+1]},tokenizer,max_length)
  if reason:return None,reason
  spans.append((encoded['prompt_length'],len(encoded['input_ids'])));prefixes.append(encoded);indices.append(index)
 if not prefixes or source['messages'][-1].get('role')!='assistant':return None,'missing_assistant_target'
 full=prefixes[-1]
 for encoded,(start,end) in zip(prefixes,spans):
  if start>=end or list(full['input_ids'][:end])!=list(encoded['input_ids']):return None,'conversation_prefix_mismatch'
 if any(a[1]>b[0] for a,b in zip(spans,spans[1:])):return None,'overlapping_assistant_spans'
 full['supervised_ranges']=spans
 identity=prefix_identity(source,indices[-1]);identity.update(encoding_mode='all_assistant_turns',supervised_assistant_indices=indices)
 identity['sample_id']=hashlib.sha256(json.dumps(identity,ensure_ascii=False,sort_keys=True).encode()).hexdigest();full['prefix_identity']=identity
 return full,None

def tokenize_dialogues(path,tokenizer,max_length,limit,encode_completion):
 rows=[];stats=Counter()
 with Path(path).open(encoding='utf-8') as stream:
  for line in stream:
   if limit>0 and len(rows)>=limit:break
   source=json.loads(line);stats['read']+=1;stats['candidate_examples']+=1;turns=sum(m.get('role')=='assistant' for m in source['messages']);stats['candidate_turns']+=turns
   encoded,reason=encode_dialogue(source,tokenizer,max_length,encode_completion)
   if reason:stats[reason]+=1;continue
   rows.append(encoded);stats['kept']+=1;stats['covered_assistant_turns']+=turns;stats['tokens']+=len(encoded['input_ids']);stats['supervised_tokens']+=sum(end-start for start,end in encoded['supervised_ranges']);stats['max_tokens']=max(stats['max_tokens'],len(encoded['input_ids']))
 if not rows:raise ValueError('No usable full conversations')
 if any(stats[k] for k in ('template_prefix_mismatch','token_prefix_mismatch','conversation_prefix_mismatch','overlapping_assistant_spans')):raise ValueError('Full conversation alignment mismatch')
 return rows,{**stats,'encoding_mode':'all_assistant_turns','example_unit':'complete_conversation'}

def label_values(item,pad_token_id,width):
 ids=list(item['input_ids']);labels=[-100]*len(ids)
 if 'supervised_ranges' in item:
  previous=0
  for start,end in item['supervised_ranges']:
   if not (previous<=start<end<=len(ids)):raise ValueError('Invalid assistant span')
   labels[start:end]=ids[start:end];previous=end
 else:labels[item['prompt_length']:]=ids[item['prompt_length']:]
 return labels+[-100]*(width-len(ids))
