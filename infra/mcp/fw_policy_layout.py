"""Offline nft ruleset inventory and bounded project-NAT merge candidate.

No shell, network, kernel mutation, or implicit policy decisions. Docker
ownership and every original rule remain visible in the inventory. A generated
transaction is a review artifact, not evidence of syntax or traffic validation.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path


def objects(value):
    if not isinstance(value,dict) or not isinstance(value.get('nftables'),list):
        raise ValueError('native_nft_ruleset_required')
    return [(kind,obj) for row in value['nftables'] if isinstance(row,dict)
            for kind,obj in row.items() if isinstance(obj,dict)]


def references(expr):
    result=[]
    for item in expr:
        if not isinstance(item,dict):continue
        for verb in ('jump','goto'):
            ref=item.get(verb)
            if isinstance(ref,dict) and isinstance(ref.get('target'),str):result.append(ref['target'])
    return result


def layout(value):
    rows=objects(value);chains={};tables={};rules=[]
    for kind,obj in rows:
        if kind=='table':tables[(obj['family'],obj['name'])]={'chains':0,'rules':0,'sets':0}
        elif kind=='chain':chains[(obj['family'],obj['table'],obj['name'])]=obj
        elif kind=='rule':rules.append(obj)
    reach={key:set() for key in chains};roles={key:set() for key in chains}
    for key,c in chains.items():
        if c.get('hook'):
            reach[key].add(c['hook'].upper())
            roles[key].add('NAT' if c.get('type')=='nat' else 'MANGLE' if c.get('prio')==-150 else c['hook'].upper())
    for _ in range(len(chains)+1):
        changed=False
        for r in rules:
            key=(r['family'],r['table'],r['chain'])
            if key not in reach:raise ValueError('missing_rule_chain')
            for target in references(r.get('expr',[])):
                dest=(r['family'],r['table'],target)
                if dest not in reach:raise ValueError('missing_jump_target')
                previous=(len(reach[dest]),len(roles[dest]));reach[dest]|=reach[key];roles[dest]|=roles[key]
                changed|=(len(reach[dest]),len(roles[dest]))!=previous
        if not changed:break
    grouped={};details=[]
    for r in rules:
        key=(r['family'],r['table'],r['chain']);kinds=roles.get(key,set())
        expr=r.get('expr',[])
        nat=any(any(k in item for k in ('snat','dnat','masquerade','redirect')) or
            item.get('xt',{}).get('name') in ('DNAT','SNAT','MASQUERADE','REDIRECT') for item in expr if isinstance(item,dict))
        mangle=any('mangle' in item or 'tproxy' in item or item.get('xt',{}).get('name') in (
            'MARK','CONNMARK','DSCP','TOS','TTL','HL','TCPMSS','SECMARK','CONNSECMARK') for item in expr if isinstance(item,dict))
        group='NAT' if nat or 'NAT' in kinds else 'MANGLE' if mangle or 'MANGLE' in kinds else next(iter(kinds)) if len(kinds)==1 else 'MULTI_HOOK' if kinds else 'UNATTACHED'
        if r['chain'].startswith('CAPSTONE-'):owner='project_in_docker_chain'
        elif r['table'].startswith('capstone_'):owner='project'
        elif r['table'] in ('nat','filter','raw','mangle'):owner='docker_or_xtables'
        else:owner='unconfirmed'
        row={'family':r['family'],'table':r['table'],'chain':r['chain'],'handle':r.get('handle'),
            'group':group,'hooks':sorted(reach[key]),'owner':owner}
        details.append(row);grouped[group]=grouped.get(group,0)+1
    for kind,obj in rows:
        if kind in ('chain','rule','set','map'):
            key=(obj['family'],obj['table']);t=tables.setdefault(key,{'chains':0,'rules':0,'sets':0})
            t[{'chain':'chains','rule':'rules','set':'sets','map':'sets'}[kind]]+=1
    return {'schema':1,'rule_count':len(rules),'grouped_rule_count':sum(grouped.values()),
        'groups':dict(sorted(grouped.items())),
        'tables':[{'family':k[0],'table':k[1],**v,'unused_proven':False} for k,v in sorted(tables.items())],
        'chains':[{'family':k[0],'table':k[1],'chain':k[2],'hooks':sorted(reach[k]),
            'base_hook':c.get('hook'),'priority':c.get('prio'),'policy':c.get('policy')} for k,c in chains.items()],
        'rules':details,'limits':['ownership is inferred; reconcile with persistence/service sources',
            'unattached or zero-counter objects are not proven unused','multi-hook rules count once; hooks list preserves scope']}


def nat_merge_candidate(value):
    """Preserve the three legacy IPv4 NAT expressions in existing inet table.

    Refuse extra objects/unknown topology. No helper assumes that Docker or
    host-filter tables can be deleted. Persistence and live validation remain
    explicit prerequisites in the output.
    """
    rows=objects(value);wanted={'capstone_gw','capstone_fwd'}
    selected=[(k,o) for k,o in rows if o.get('family')=='ip' and
        (o.get('name') if k=='table' else o.get('table')) in wanted]
    if any(k not in ('table','chain','rule') for k,o in selected):raise ValueError('unexpected_nat_object')
    if (len([1 for k,o in selected if k=='table'])!=2 or
            {(o['family'],o['name']) for k,o in selected if k=='table'}!={('ip',n) for n in wanted}):raise ValueError('legacy_nat_tables_missing')
    if not any(k=='table' and o.get('family')=='inet' and o.get('name')=='capstone_fw' for k,o in rows):raise ValueError('host_table_missing')
    if any(k=='chain' and o.get('family')=='inet' and o.get('table')=='capstone_fw' and
           o.get('name') in ('nat_prerouting','nat_postrouting') for k,o in rows):raise ValueError('candidate_chains_already_exist')
    expected={('capstone_gw','postrouting'):('postrouting',100),('capstone_fwd','prerouting'):('prerouting',-100),('capstone_fwd','postrouting'):('postrouting',100)}
    cs={(o['table'],o['name']):o for k,o in selected if k=='chain'}
    if len([1 for k,o in selected if k=='chain'])!=3 or set(cs)!=set(expected):raise ValueError('legacy_nat_chains_changed')
    for key,(hook,priority) in expected.items():
        c=cs[key]
        if c.get('type')!='nat' or c.get('hook')!=hook or c.get('prio')!=priority or c.get('policy')!='accept':raise ValueError('legacy_nat_hook_changed')
    rs=[o for k,o in selected if k=='rule']
    if len(rs)!=3 or { (r['table'],r['chain']) for r in rs}!=set(expected):raise ValueError('legacy_nat_rules_changed')
    commands=[{'add':{'chain':{'family':'inet','table':'capstone_fw','name':'nat_'+hook,
        'type':'nat','hook':hook,'prio':priority,'policy':'accept'}}} for hook,priority in [('prerouting',-100),('postrouting',100)]]
    for r in rs:
        expr=copy.deepcopy(r['expr'])
        if sum('dnat' in item or 'masquerade' in item for item in expr)!=1:raise ValueError('unexpected_nat_statement')
        for item in expr:
            if 'dnat' in item:item['dnat']['family']='ip'
        # Original ip-family rules could never NAT IPv6. Preserve that boundary.
        expr.insert(0,{'match':{'op':'==','left':{'meta':{'key':'nfproto'}},'right':'ipv4'}})
        commands.append({'add':{'rule':{'family':'inet','table':'capstone_fw','chain':'nat_'+r['chain'],'expr':expr}}})
    commands += [{'delete':{'table':{'family':'ip','name':name}}} for name in sorted(wanted)]
    return {'schema':1,'status':'candidate_not_validated','affected_old_tables':['ip capstone_gw','ip capstone_fwd'],
        'target':'inet capstone_fw','preserved_host_filter_and_block_sets':True,'copied_nat_rules':3,
        'transaction':{'nftables':commands},'prerequisites':[
            'verify target kernel/nft supports inet NAT; validate JSON using nft --check',
            'check hook ordering/overlap with installed Docker backend in isolated network namespace',
            'update persistent loader, boot unit, initial installer and old-table references together',
            'preserve active containment sets/TTL, management path and exact CAS rollback',
            'new administrator IP is pending; do not apply access lockout policy now',
            'finish model comparison before changing its live read target']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input',type=Path)
    p.add_argument('--merge-candidate',action='store_true');args=p.parse_args()
    raw=args.input.read_bytes();value=json.loads(raw)
    result=nat_merge_candidate(value) if args.merge_candidate else layout(value)
    result['input_sha256']=hashlib.sha256(raw).hexdigest()
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
