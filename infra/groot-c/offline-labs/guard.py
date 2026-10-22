"""Independent nftables boundary for the dedicated offline lab bridge."""
import json
import os
import subprocess
import sys

NFT = '/usr/sbin/nft'
TABLE = 'capstone_offline_labs'
BRIDGE = 'br-offline-labs'
RULES = '''table inet capstone_offline_labs {
 chain input {
  type filter hook input priority -20; policy accept;
  iifname "br-offline-labs" ct state established,related accept
  iifname "br-offline-labs" drop
 }
 chain forward {
  type filter hook forward priority -20; policy accept;
  iifname "br-offline-labs" drop
  oifname "br-offline-labs" drop
 }
}
'''


def interface_expr(name):
    return {'match': {'op': '==', 'left': {'meta': {'key': name}}, 'right': BRIDGE}}


def validate_rules(document):
    tables, chains, rules = [], {}, {'input': [], 'forward': []}
    for item in document.get('nftables', []):
        if 'metainfo' in item:
            continue
        if 'table' in item:
            t = item['table']; tables.append((t['family'], t['name']))
        elif 'chain' in item:
            c = item['chain']
            if c['name'] in chains:
                raise RuntimeError('guard_duplicate_chain')
            chains[c['name']] = {k: c.get(k) for k in ('family', 'table', 'type', 'hook', 'prio', 'policy')}
        elif 'rule' in item:
            r = item['rule']
            if r.get('family') != 'inet' or r.get('table') != TABLE or r.get('chain') not in rules:
                raise RuntimeError('guard_unexpected_rule')
            rules[r['chain']].append(r['expr'])
        else:
            raise RuntimeError('guard_unexpected_object')
    if tables != [('inet', TABLE)] or set(chains) != {'input', 'forward'}:
        raise RuntimeError('guard_missing_chain')
    for name, c in chains.items():
        if c != {'family': 'inet', 'table': TABLE, 'type': 'filter', 'hook': name, 'prio': -20, 'policy': 'accept'}:
            raise RuntimeError('guard_chain_changed')
    expected = {
        'input': [[interface_expr('iifname'), {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': ['established', 'related']}}, {'accept': None}], [interface_expr('iifname'), {'drop': None}]],
        'forward': [[interface_expr('iifname'), {'drop': None}], [interface_expr('oifname'), {'drop': None}]],
    }
    if rules != expected:
        raise RuntimeError('guard_rules_changed')
    return True


def verify_guard():
    p = subprocess.run([NFT, '-j', 'list', 'table', 'inet', TABLE], capture_output=True, text=True, timeout=5)
    if p.returncode != 0:
        raise RuntimeError('guard_missing')
    try:
        return validate_rules(json.loads(p.stdout))
    except (ValueError, KeyError, TypeError):
        raise RuntimeError('guard_invalid') from None


def install():
    if os.geteuid() != 0:
        raise RuntimeError('root_required')
    p = subprocess.run([NFT, '-j', 'list', 'table', 'inet', TABLE], capture_output=True, timeout=5)
    if p.returncode == 0:
        return verify_guard()  # Never silently overwrite an operator's changed rules.
    subprocess.run([NFT, '--check', '-f', '-'], input=RULES, text=True, check=True, timeout=5)
    subprocess.run([NFT, '-f', '-'], input=RULES, text=True, check=True, timeout=5)
    return verify_guard()


if __name__ == '__main__':
    if sys.argv[1:] == ['install']:
        install()
    elif sys.argv[1:] == ['check']:
        verify_guard()
    else:
        raise SystemExit('usage: guard.py install|check')
    print('offline network guard verified')
