"""Atomic same-directory create without overwrite or a hard-link crash window.

Uses existing libc only: Linux renameat2(RENAME_NOREPLACE), Darwin's equivalent
for local fixtures. Unsupported platforms/filesystems fail; no link fallback.
No CLI, paths, source payloads, commands or permission changes.
"""
import ctypes
import errno
import os
import re
import stat
import sys


def create(parent,temporary,name):
    if type(parent)is not int or parent<0 or temporary==name:
        raise ValueError('atomic_create_scope')
    for value in (temporary,name):
        if not isinstance(value,str)or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,255}',value)or value in ('.','..'):
            raise ValueError('atomic_create_scope')
    if not stat.S_ISDIR(os.fstat(parent).st_mode):raise ValueError('atomic_create_directory')
    source=os.stat(temporary,dir_fd=parent,follow_symlinks=False)
    if not stat.S_ISREG(source.st_mode)or source.st_nlink!=1:raise ValueError('atomic_create_source')
    library=ctypes.CDLL(None,use_errno=True)
    if sys.platform=='linux':function=getattr(library,'renameat2',None);flag=1
    elif sys.platform=='darwin':function=getattr(library,'renameatx_np',None);flag=4
    else:function=None
    if function is None:raise OSError(errno.ENOTSUP,'atomic no-replace rename is unavailable')
    function.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    function.restype=ctypes.c_int
    if function(parent,os.fsencode(temporary),parent,os.fsencode(name),flag)!=0:
        code=ctypes.get_errno();raise OSError(code,os.strerror(code),name)
