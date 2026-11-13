"""Shared, bounded workflow text. No tools, risk decisions or authority changes."""
from functools import lru_cache
from pathlib import Path
import re

MARKERS={
    'soc-query':'SOC_WORKFLOW_QUERY_V1',
    'soc-investigate':'SOC_WORKFLOW_INVESTIGATE_V1',
    'soc-change':'SOC_WORKFLOW_CHANGE_V1',
    'soc-recover':'SOC_WORKFLOW_RECOVER_V1',
}
SECTIONS={'service-investigation':('soc-investigate','## 서비스 원인 조사'),
          'peer-review':('soc-investigate','## 교차 검토 대조')}
# Loaded only by their own phase (the peer review), never in the full
# workflow body of an investigation or query prompt.
SECTION_ONLY=frozenset({'peer-review'})

def policy_text(name,raw):
    if name not in MARKERS:raise ValueError('soc_workflow_unknown')
    if not isinstance(raw,bytes) or not 1<=len(raw)<=24576:raise ValueError('soc_workflow_size')
    text=raw.decode('utf-8');parts=text.split('---\n',2)
    if (len(parts)!=3 or parts[0] or not re.search(r'^name: '+re.escape(name)+r'$',parts[1],re.M)
            or not re.search(r'^description: \S[^\r\n]+$',parts[1],re.M)):
        raise ValueError('soc_workflow_frontmatter')
    body=parts[2].strip()
    if body.count(MARKERS[name])!=1:raise ValueError('soc_workflow_marker')
    return body

@lru_cache(maxsize=16)
def _blocks(names,directory=None):
    if not isinstance(names,tuple) or len(names)!=len(set(names)) or any(n not in MARKERS for n in names):
        raise ValueError('soc_workflow_selection')
    here=Path(__file__).resolve().parent if directory is None else Path(directory)
    blocks=[]
    for name in names:
        path=here/'skills'/name/'SKILL.md'
        flat=here/('skill-'+name+'.md')
        if any(p.is_symlink() for p in (here/'skills',path.parent,path,flat)):
            raise ValueError('soc_workflow_missing_or_unsafe')
        paths=[p for p in (path,flat) if p.is_file()]
        if len(paths)!=1:raise ValueError('soc_workflow_missing_or_ambiguous')
        path=paths[0]
        blocks.append(policy_text(name,path.read_bytes()))
    return tuple(blocks)


def _without_section_only(name,block):
    for section in SECTION_ONLY:
        skill,heading=SECTIONS[section]
        if skill==name:
            block=re.sub(r'^'+re.escape(heading)+r'\s*$.*?(?=^#{1,2} |\Z)','',block,flags=re.M|re.S).rstrip()
    return block


def policy(names,directory=None):
    blocks=_blocks(names,directory)
    return '\n\n'.join(_without_section_only(n,b) for n,b in zip(names,blocks))


def section_policy(names, section, directory=None):
    """Load one explicit part of a validated skill for a focused model phase."""
    if section not in SECTIONS or names!=(SECTIONS[section][0],):
        raise ValueError('soc_workflow_section_selection')
    name,heading=SECTIONS[section];body='\n\n'.join(_blocks(names,directory))
    matches=list(re.finditer(r'^'+re.escape(heading)+r'\s*$',body,re.M))
    if len(matches)!=1:raise ValueError('soc_workflow_section_missing_or_duplicate')
    rest=body[matches[0].end():]
    stop=re.search(r'^#{1,2} ',rest,re.M)
    selected=rest[:stop.start()] if stop else rest
    if not selected.strip():raise ValueError('soc_workflow_section_empty')
    return MARKERS[name]+'\n'+heading+'\n'+selected.strip()
