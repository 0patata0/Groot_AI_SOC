"""Separate valid top-level Markdown tables from prose without changing cells.

Only blank lines are inserted. Fenced/indented code, quotes, raw HTML blocks,
and malformed table-like text are preserved. No model or tool is called.
"""
import re

_ROW = re.compile(r'^ {0,3}\|.*\|[ \t]*$')
_FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
_RAW = re.compile(r'^ {0,3}<(pre|script|style|textarea)(?:\s|>)',re.I)


def _cells(line):
    return re.split(r'(?<!\\)\|',line.strip()[1:-1])


def normalize_tables(text):
    if not isinstance(text,str):raise TypeError('Markdown text must be a string')
    if '|' not in text:return text
    lines=text.splitlines(keepends=True)
    out=[];i=0;fence=None;raw=None
    while i<len(lines):
        line=lines[i];body=line.rstrip('\r\n')
        marker=_FENCE.match(body)
        if fence:
            out.append(line);i+=1
            if marker and marker[1][0]==fence[0] and len(marker[1])>=len(fence) and not marker[2].strip():fence=None
            continue
        if raw:
            out.append(line);i+=1
            if re.search(r'</'+raw+r'\s*>',body,re.I):raw=None
            continue
        if marker:
            fence=marker[1];out.append(line);i+=1;continue
        html=_RAW.match(body)
        if html:
            raw=html[1]
            if re.search(r'</'+raw+r'\s*>',body,re.I):raw=None
            out.append(line);i+=1;continue
        separator=lines[i+1].rstrip('\r\n') if i+1<len(lines) else ''
        valid=(_ROW.fullmatch(body) and _ROW.fullmatch(separator)
               and len(_cells(body))==len(_cells(separator))>=2
               and all(re.fullmatch(r'\s*:?-{3,}:?\s*',cell) for cell in _cells(separator)))
        if not valid:out.append(line);i+=1;continue
        ending='\r\n' if line.endswith('\r\n') else '\n'
        if out and out[-1].strip():out.append(ending)
        out.extend(lines[i:i+2]);i+=2
        while i<len(lines) and _ROW.fullmatch(lines[i].rstrip('\r\n')):
            out.append(lines[i]);i+=1
        if i<len(lines) and lines[i].strip():out.append(ending)
    return ''.join(out)
