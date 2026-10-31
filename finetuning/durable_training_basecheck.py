"""Read-only full base artifact hashing, with a receipt in the new run only."""
import hashlib,json,sys,time
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from download_model import verify_artifact

def main():
    root=Path(sys.argv[1]).resolve();base=root.parents[1]
    out=root/'base-recheck.json'
    if out.exists():raise ValueError('Do not replace an existing base proof')
    started=time.monotonic();raw=(base/'base-manifest.json').read_bytes();manifest=json.loads(raw)
    if not manifest['verified'] or manifest['revision']!='995ad96eacd98c81ed38be0c5b274b04031597b0':raise ValueError('Unexpected base')
    value={'status':'running','started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat()}
    try:
        files=[]
        for item in manifest['files']:
            path=base/'base'/item['path'];before=path.stat();verify_artifact(base/'base',item);after=path.stat()
            if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Artifact changed while hashing')
            files.append({'path':item['path'],'size':after.st_size,'mtime_ns':after.st_mtime_ns})
        value.update(status='passed',files=files,manifest_sha256=hashlib.sha256(raw).hexdigest())
    except BaseException as exc:
        value.update(status='failed',error_type=type(exc).__name__);raise
    finally:
        value.update(elapsed_seconds=time.monotonic()-started,at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat())
        tmp=out.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2)+'\n');tmp.replace(out)

if __name__=='__main__':main()
