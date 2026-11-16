"""Deterministic policy-file candidates; no file or operating-system writes.

Fixed adapters collect the original bytes and bind the complete candidate to
approval. A model never supplies a path, shell fragment or source-file body.
"""
import importlib.util
from pathlib import Path
import re
import shlex

s=importlib.util.spec_from_file_location('_management_render_contract',Path(__file__).with_name('management_policy.py'))
contract=importlib.util.module_from_spec(s);s.loader.exec_module(contract)
BEGIN='# BEGIN CAPSTONE_MANAGEMENT_SOURCES'
END='# END CAPSTONE_MANAGEMENT_SOURCES'
FORWARD='    F -s "$MGMT_DNAT_SRC" -d "$ip" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$ipt" -m conntrack --ctstate NEW -j ACCEPT'
FORWARD_MULTI=('    for management_source in "${MGMT_DNAT_SOURCES[@]}"; do\n'
 '      F -s "$management_source" -d "$ip" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$ipt" -m conntrack --ctstate NEW -j ACCEPT\n'
 '    done')
ARGUMENTS=('NAT_ARGS=()\n'
 'for management_source in "${MGMT_DNAT_SOURCES[@]}"; do\n'
 '  NAT_ARGS+=(--management-source "$management_source")\n'
 'done\n')


def once(text, old, new):
    if text.count(old)!=1:
        raise ValueError('management_loader_unique_anchor_required')
    return text.replace(old,new,1)


def block(cidrs):
    return BEGIN+'\nMGMT_DNAT_SOURCES=('+ ' '.join(shlex.quote(x)for x in contract.addresses(cidrs))+')\n'+END


def loader_text(raw):
    if not isinstance(raw,bytes)or len(raw)>256*1024 or b'\r'in raw:
        raise ValueError('management_loader_bytes')
    text=raw.decode('utf-8')
    if not text.startswith('#!/bin/bash\n')or not text.endswith('\n'):
        raise ValueError('management_loader_format')
    return text


def current_native_sources(raw):
    text=loader_text(raw)
    if BEGIN in text or END in text:
        if text.count(BEGIN)!=1 or text.count(END)!=1:
            raise ValueError('management_loader_block_count')
        start=text.index(BEGIN);end=text.index(END,start)+len(END);body=text[start:end]
        m=re.fullmatch(re.escape(BEGIN)+r'\nMGMT_DNAT_SOURCES=\(([^\n]*)\)\n'+re.escape(END),body)
        if not m:
            raise ValueError('management_loader_block_format')
        cidrs=contract.addresses(shlex.split(m[1]))
        if body!=block(cidrs):
            raise ValueError('management_loader_block_noncanonical')
        return cidrs
    matches=list(re.finditer(r'^MGMT_DNAT_SRC="([0-9./]+)"[^\n]*$',text,re.M))
    if len(matches)!=1:
        raise ValueError('management_loader_source_assignment')
    return contract.addresses([matches[0][1]])


def native_loader(raw, cidrs):
    """Change the one reviewed gateway loader to an explicit administrator list.

    Existing forwarded destinations, firewall/egress policies and block TTL
    restore logic stay byte-identical. The full candidate still requires an
    exact global approval, syntax checks and actual load/route verification.
    """
    text=loader_text(raw);current=current_native_sources(raw);future=block(cidrs)
    if BEGIN in text:
        start=text.index(BEGIN);end=text.index(END,start)+len(END)
        text=once(text,text[start:end],future)
    else:
        match=re.search(r'^MGMT_DNAT_SRC="[0-9./]+"[^\n]*$',text,re.M)
        text=once(text,match[0],future)
        text=once(text,FORWARD,FORWARD_MULTI)
        text=once(text,'NAT_ARGS=()\n',ARGUMENTS)
        text=once(text,' --management-source "$MGMT_DNAT_SRC"','')
        lines=[line for line in text.splitlines()if '$MGMT_DNAT_SRC'in line]
        if len(lines)!=1 or not lines[0].startswith('echo '):
            raise ValueError('management_loader_unknown_scalar_use')
        text=once(text,lines[0],lines[0].replace('$MGMT_DNAT_SRC','${MGMT_DNAT_SOURCES[*]}'))
    if ('$MGMT_DNAT_SRC'in text or text.count(FORWARD_MULTI)!=1 or text.count(ARGUMENTS)!=1
            or current_native_sources(text.encode())!=contract.addresses(cidrs)):
        raise ValueError('management_loader_integration_drift')
    return text.encode('utf-8')
