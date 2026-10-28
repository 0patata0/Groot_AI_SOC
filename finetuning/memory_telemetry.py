"""Read-only, best-effort training diagnostics; never initialize or clear CUDA.

Allocator counters cover this PyTorch process, not every driver/library request.
An unavailable measurement is not zero, and a sample is not a capacity guarantee.
"""
from datetime import datetime
import json
from pathlib import Path
from zoneinfo import ZoneInfo

HOST_KEYS={'MemTotal','MemFree','MemAvailable','Buffers','Cached','KReclaimable',
           'Slab','SReclaimable','SUnreclaim','CmaTotal','CmaFree','SwapTotal','SwapFree'}
VM_KEYS={'oom_kill','compact_stall','compact_fail','compact_success','allocstall_normal'}
CUDA_KEYS={'allocated_bytes.all.current','allocated_bytes.all.peak',
           'reserved_bytes.all.current','reserved_bytes.all.peak',
           'inactive_split_bytes.all.current','inactive_split_bytes.all.peak',
           'num_alloc_retries','num_ooms','num_device_alloc','num_device_free'}


def _numbers(path,keys,kib=False):
    try:
        values={}
        for line in path.read_text().splitlines():
            cells=line.replace(':','').split()
            if len(cells)>=2 and cells[0] in keys:
                value=int(cells[1])
                if value<0:raise ValueError('Negative counter')
                if kib and (len(cells)!=3 or cells[2]!='kB'):raise ValueError('Unknown memory unit')
                values[cells[0]]=value*(1024 if kib else 1)
        return {'status':'available' if values else 'unavailable','values':values}
    except (OSError,ValueError) as exc:return {'status':'unavailable','error_type':type(exc).__name__}


def collect(cuda=None,*,phase,step=None,proc=Path('/proc'),cgroup=Path('/sys/fs/cgroup'),error_type=None):
    result={'schema':1,'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
            'phase':phase,'step':step,'host_bytes':_numbers(proc/'meminfo',HOST_KEYS,True),
            'vm_cumulative_counters':_numbers(proc/'vmstat',VM_KEYS),
            'cgroup':{'namespace':'observed cgroup root'},
            'cuda':{'status':'not_initialized','scope':'current PyTorch process; not all driver allocations'}}
    if error_type:result['error_type']=error_type
    for name in ('memory.current','memory.peak','memory.max'):
        try:
            raw=(cgroup/name).read_text().strip()
            result['cgroup'][name]=None if raw=='max' else int(raw)
        except (OSError,ValueError) as exc:result['cgroup'][name]={'status':'unavailable','error_type':type(exc).__name__}
    result['cgroup']['memory.events']=_numbers(cgroup/'memory.events',{'low','high','max','oom','oom_kill','oom_group_kill'})
    if cuda is None:return result
    try:
        if not cuda.is_initialized():return result
        data=result['cuda'];data['status']='available'
        backend=getattr(cuda,'get_allocator_backend',None)
        if backend is None:backend=getattr(getattr(cuda,'memory',None),'get_allocator_backend',None)
        data['allocator_backend']=backend() if backend else None
        data['allocator_counters']={k:v for k,v in cuda.memory_stats().items() if k in CUDA_KEYS and isinstance(v,int) and not isinstance(v,bool) and v>=0}
        data['counter_caveat']='Backend-specific; zero retries does not exclude driver/library failures.'
        free,total=cuda.mem_get_info();data.update(free_bytes=free,total_bytes=total)
        snapshot=getattr(cuda,'memory_snapshot',None)
        if snapshot is not None:
            try:
                segments=snapshot()
                flags=[s.get('is_expandable') for s in segments]
                data['segments']={'status':'available','count':len(segments),
                    'expandable':sum(flags) if all(isinstance(v,bool) for v in flags) else None}
            except Exception as exc:
                data['segments']={'status':'unavailable','error_type':type(exc).__name__}
        else:data['segments']={'status':'unavailable'}
    except Exception as exc:result['cuda'].update(status='unavailable',error_type=type(exc).__name__)
    return result


def record(output,cuda=None,*,phase,step=None,error_type=None):
    result=collect(cuda,phase=phase,step=step,error_type=error_type)
    try:
        with (Path(output)/'memory_telemetry.jsonl').open('a',encoding='utf-8') as handle:
            handle.write(json.dumps(result,ensure_ascii=False)+'\n')
    except OSError as exc:result['recording_error']=type(exc).__name__
    return result
