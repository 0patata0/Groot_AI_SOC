#!/usr/bin/env python3
"""Forced-command read of a fixed sanitized web snapshot; no sudo or shell."""
import os
from pathlib import Path
import selectors
import stat
import sys
import syslog
import time
import types

LIBRARY=Path('/opt/capstone-web-evidence/web_evidence.py')


def library():
    for path in (LIBRARY.parent,*LIBRARY.parent.parents):
        meta=path.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:
            raise ValueError('unsafe_web_library_parent')
    fd=os.open(LIBRARY,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        meta=os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_nlink!=1 or meta.st_mode&0o022 or meta.st_size>131072:
            raise ValueError('unsafe_web_library')
        raw=source.read(131073)
    module=types.ModuleType('fixed_web_evidence');module.__file__=str(LIBRARY)
    exec(compile(raw,str(LIBRARY),'exec'),module.__dict__)
    return module


def incoming():
    selector=selectors.SelectSelector();fd=sys.stdin.fileno();selector.register(fd,selectors.EVENT_READ)
    raw=bytearray();deadline=time.monotonic()+2
    try:
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not selector.select(remaining):raise ValueError('input_timeout')
            data=os.read(fd,4097-len(raw))
            if not data:
                if not raw.strip():raise ValueError('request_required')
                return bytes(raw)
            raw.extend(data)
            if len(raw)>4096:raise ValueError('input_bound')
    finally:selector.close()


def main():
    if len(sys.argv)!=1 or os.environ.get('SSH_ORIGINAL_COMMAND',''):
        raise ValueError('reader_takes_no_command')
    module=library();request=module.request(__import__('json').loads(incoming(),object_pairs_hook=module.unique))
    result=module.answer(request,module.read_snapshot());raw=module.encoded(result)
    module.need(len(raw)<=262144,'result_bound')
    syslog.syslog(syslog.LOG_NOTICE,__import__('json').dumps({'event':'web_evidence_read','target':result['target'],'operation':request['operation']}))
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError):
        syslog.syslog(syslog.LOG_WARNING,'web_evidence_read unavailable')
        raise SystemExit(1) from None
