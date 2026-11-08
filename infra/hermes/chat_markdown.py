"""Separate valid top-level Markdown tables from prose without changing cells.

Normalization inserts blank lines and canonicalizes optional outer pipes.
Cell contents remain unchanged. The optional transport splitter repeats
table headers across posts without dropping rows. Fenced/indented code, quotes,
raw HTML blocks, and malformed table-like text use the original splitter.
No model or tool is called.
"""
import re

_ROW = re.compile(r'^ {0,3}\|.*\|[ \t]*$')
_FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')
_RAW = re.compile(r'^ {0,3}<(pre|script|style|textarea)(?:\s|>)',re.I)


def _cells(line):
    return re.split(r'(?<!\\)\|',line.strip()[1:-1])


def _bordered_row(line):
    if _ROW.fullmatch(line):return line
    if (line.startswith(('    ','\t')) or _FENCE.match(line)
            or re.match(r'^ {0,3}(?:>|<|[-*+]\s|[0-9]+[.)]\s)',line)):
        return None
    value=line.strip()
    if not re.search(r'(?<!\\)\|',value):return None
    if not value.startswith('|'):value='|'+value
    if not value.endswith('|') or value.endswith('\\|'):value+='|'
    return value if len(_cells(value))>=2 else None


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
        header_row=_bordered_row(body);separator_row=_bordered_row(separator)
        valid=(header_row is not None and separator_row is not None
               and len(_cells(header_row))==len(_cells(separator_row))>=2
               and all(re.fullmatch(r'\s*:?-{3,}:?\s*',cell) for cell in _cells(separator_row)))
        if not valid:out.append(line);i+=1;continue
        ending='\r\n' if line.endswith('\r\n') else '\n'
        if out and out[-1].strip():out.append(ending)
        out.append(header_row+line[len(body):])
        out.append(separator_row+lines[i+1][len(separator):]);i+=2
        while i<len(lines):
            raw_row=lines[i].rstrip('\r\n');row=_bordered_row(raw_row)
            if row is None:break
            out.append(row+lines[i][len(raw_row):]);i+=1
        if i<len(lines) and lines[i].strip():out.append(ending)
    return ''.join(out)


def _table_spans(lines):
    """Find the same top-level pipe tables accepted by normalize_tables."""
    spans=[];i=0;fence=None;raw=None
    while i<len(lines):
        body=lines[i].rstrip('\r\n');marker=_FENCE.match(body)
        if fence:
            if marker and marker[1][0]==fence[0] and len(marker[1])>=len(fence) and not marker[2].strip():fence=None
            i+=1;continue
        if raw:
            if re.search(r'</'+raw+r'\s*>',body,re.I):raw=None
            i+=1;continue
        if marker:fence=marker[1];i+=1;continue
        html=_RAW.match(body)
        if html:
            raw=html[1]
            if re.search(r'</'+raw+r'\s*>',body,re.I):raw=None
            i+=1;continue
        separator=lines[i+1].rstrip('\r\n') if i+1<len(lines) else ''
        if (_ROW.fullmatch(body) and _ROW.fullmatch(separator)
            and len(_cells(body))==len(_cells(separator))>=2
            and all(re.fullmatch(r'\s*:?-{3,}:?\s*',cell) for cell in _cells(separator))):
            start=i;i+=2
            while i<len(lines) and _ROW.fullmatch(lines[i].rstrip('\r\n')):i+=1
            spans.append((start,i))
        else:i+=1
    return spans


def labeled_report_tables(text):
    """Format parallel labelled report bullets, preserving values and decisions.

    Only standalone, fully labelled blocks with at least two values qualify.
    Unlabelled/continued lists, code, quotes, HTML and existing tables stay as-is.
    No model text is summarized or replaced by a controller decision.
    """
    if not isinstance(text,str):raise TypeError('Markdown text must be a string')
    lines=text.splitlines(keepends=True)
    if re.search(r'(?m)^ {0,3}<[A-Za-z!/]',text):return text
    def rows(block):
        result=[];parent=None;used=False
        for line in block:
            item=re.fullmatch(r'( {0,2})[-*][ \t]+(.*)',line.rstrip('\r\n'))
            if not item or len(item[1]) not in (0,2):return None
            body=item[2]
            if re.search(r'```|~~~|<[A-Za-z!/][^>]*>',body):return None
            pair=re.fullmatch(r'\*\*(.{1,120}?)\*\*[ \t]*[:：][ \t]*(.*)',body)
            if pair is None:
                pair=re.fullmatch(r'([^:*`][^:：]{0,119})[:：][ \t]*(.*)',body)
            if pair is None:return None
            key,value=pair[1].strip(),pair[2]
            if not key or '**' in key:return None
            if not item[1]:
                if parent and not used:return None
                parent=None;used=False
                if not value:
                    parent=key;continue
            elif not parent or not value:return None
            if parent:key=parent+' / '+key;used=True
            if not value:return None
            result.append((key,value))
        return result if len(result)>=2 and (not parent or used) else None
    def cell(value):
        return re.sub(r'(\\*)\|',lambda m:m[1]+('\\' if len(m[1])%2==0 else '')+'|',value)
    out=[];i=0;fence=None;raw=None
    while i<len(lines):
        line=lines[i];body=line.rstrip('\r\n');marker=_FENCE.match(body)
        if fence:
            out.append(line);i+=1
            if marker and marker[1][0]==fence[0] and len(marker[1])>=len(fence) and not marker[2].strip():fence=None
            continue
        if raw:
            out.append(line);i+=1
            if re.search(r'</'+raw+r'\s*>',body,re.I):raw=None
            continue
        if marker:fence=marker[1];out.append(line);i+=1;continue
        html=_RAW.match(body)
        if html:
            raw=html[1] if not re.search(r'</'+html[1]+r'\s*>',body,re.I) else None
            out.append(line);i+=1;continue
        if not re.match(r'^[-*][ \t]+',body) or i and lines[i-1].strip():
            out.append(line);i+=1;continue
        end=i+1
        while end<len(lines) and lines[end].strip() and re.match(r'^(?:[-*][ \t]|[ \t])',lines[end]):end+=1
        values=rows(lines[i:end]) if end==len(lines) or not lines[end].strip() else None
        if values is None:out.extend(lines[i:end]);i=end;continue
        nl='\r\n' if line.endswith('\r\n') else '\n'
        table=['| 확인 항목 | 보고 내용 |','| --- | --- |']+['| '+cell(k)+' | '+cell(v)+' |' for k,v in values]
        out.append(nl.join(table)+(nl if lines[end-1].endswith(('\n','\r')) else ''));i=end
    return ''.join(out)


def split_tables(text, max_length=4000, len_fn=None, *, fallback):
    """Split recognized tables at row boundaries and repeat their exact header.

    The pinned native splitter remains responsible for prose and code fences.
    Non-table messages, unsupported oversized rows/headers, or an unexpected
    native split contract return its unchanged result. That fallback preserves
    content but cannot promise a valid table for a row larger than one post.
    """
    measure=len_fn or len
    if '|' not in text:
        return fallback(text,max_length,len_fn)
    normalized=normalize_tables(text)
    if measure(normalized)<=max_length:
        return fallback(normalized,max_length,len_fn)
    lines=normalized.splitlines(keepends=True)
    spans=_table_spans(lines)
    if not spans:return fallback(text,max_length,len_fn)
    # More conservative than the actual part count; reserve before packing so
    # indicators can never push a complete row over the platform limit.
    bound=max(1,len(normalized))
    budget=max_length-measure(f'\n\n({bound}/{bound})')
    if budget<=0:return fallback(text,max_length,len_fn)
    for start,end in spans:
        header=''.join(lines[start:start+2])
        if measure(header)>budget or any(measure(header+row)>budget for row in lines[start+2:end]):
            return fallback(text,max_length,len_fn)
    chunks=[];current=''

    def flush():
        nonlocal current
        if current.strip():chunks.append(current)
        current=''

    def prose(value):
        nonlocal current
        if measure(current+value)<=budget:
            current+=value;return True
        flush()
        parts=fallback(value,budget,len_fn)
        if len(parts)>1:
            bodies=[]
            for index,part in enumerate(parts,1):
                suffix=f' ({index}/{len(parts)})'
                if not part.endswith(suffix):return False
                bodies.append(part[:-len(suffix)])
            parts=bodies
        for index,part in enumerate(parts):
            if measure(part)>budget:return False
            if index:flush()  # native continuations are already standalone
            if measure(current+part)>budget:flush()
            current+=part
        return True

    cursor=0
    for start,end in spans:
        if not prose(''.join(lines[cursor:start])):return fallback(text,max_length,len_fn)
        header=''.join(lines[start:start+2]);rows=lines[start+2:end]
        # A new table and every continuation are standalone Markdown blocks.
        gap='' if not current or current.endswith('\n\n') or current.endswith('\r\n\r\n') else ('\n' if current.endswith('\n') else '\n\n')
        first=header+(rows[0] if rows else '')
        if measure(current+gap+first)>budget:flush();gap=''
        current+=gap+header
        for row in rows:
            if measure(current+row)>budget:
                flush();current=header
            current+=row
        cursor=end
    if not prose(''.join(lines[cursor:])):return fallback(text,max_length,len_fn)
    flush()
    if len(chunks)>1:chunks=[part+f'\n\n({i}/{len(chunks)})' for i,part in enumerate(chunks,1)]
    if not chunks or any(measure(part)>max_length for part in chunks):return fallback(text,max_length,len_fn)
    return chunks
