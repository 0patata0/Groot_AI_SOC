"""CPU-only token admission for the joint source batch; never load weights."""
import hashlib
import json
import sys
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo


def main(base):
    from transformers import AutoTokenizer
    from train import encode_completion
    from dialogue_encoding import encode_dialogue
    tokenizer=AutoTokenizer.from_pretrained(base,trust_remote_code=False,local_files_only=True)
    results=[];source_digest=hashlib.sha256()
    for line in sys.stdin.buffer:
        source_digest.update(line);item=json.loads(line);row=item['row']
        encoded,reason=encode_dialogue(row,tokenizer,4096,encode_completion)
        results.append({'id':row['id'],'split':item['split'],'reason':reason,
                        'tokens':len(encoded['input_ids'])if encoded else None})
    artifacts={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in Path(base).iterdir()
               if p.is_file()and p.name in ('tokenizer.json','tokenizer_config.json','chat_template.jinja','config.json')}
    print(json.dumps({'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                      'input_sha256':source_digest.hexdigest(),'max_length':4096,'truncation':False,
                      'tokenizer_class':type(tokenizer).__name__,'artifacts':artifacts,'records':results,
                      'weights_loaded':False,'gpu_training_started':False},ensure_ascii=False))


if __name__=='__main__':main(sys.argv[1])
