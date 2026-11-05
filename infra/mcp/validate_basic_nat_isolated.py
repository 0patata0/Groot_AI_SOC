"""Exercise the three project NAT rules in disposable Linux namespaces.

Requires root and existing ip/nft/python3. Never applies nft rules to the host.
Checks NAT translation parity only; Docker, host filtering and containment TTL
are deliberately outside this fixture and need separate operating validation.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

from fw_policy_layout import nat_merge_candidate, objects


def command(args, *, data=None, check=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(json.dumps({'command': args, 'rc': result.returncode,
                                       'stderr': result.stderr[:1200]}))
    return result


def host_policy_fingerprint():
    snapshot = json.loads(command(['nft', '-j', '-a', '-n', 'list', 'ruleset']).stdout)

    def strip(value):
        if isinstance(value, list):
            return [strip(v) for v in value]
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items()
                    if k not in ('handle', 'packets', 'bytes', 'expires')}
        return value

    # Live set elements/expiry can legitimately change in the running SOC.
    structure = [strip(item) for item in snapshot['nftables']
                 if any(k in item for k in ('table', 'chain', 'rule'))]
    return hashlib.sha256(json.dumps(structure, sort_keys=True).encode()).hexdigest()


def legacy_commands(snapshot):
    result = []
    for kind, obj in objects(snapshot):
        name = obj.get('name') if kind == 'table' else obj.get('table')
        if obj.get('family') != 'ip' or name not in ('capstone_gw', 'capstone_fwd'):
            continue
        if kind not in ('table', 'chain', 'rule'):
            raise ValueError('unexpected_legacy_object')
        clean = {k: copy.deepcopy(v) for k, v in obj.items()
                 if k not in ('handle', 'index', 'position')}
        result.append({'add': {kind: clean}})
    return result


SERVER = """import http.server,json,sys
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  raw=json.dumps({'peer':self.client_address[0],'path':self.path}).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def log_message(self,*args):pass
http.server.HTTPServer((sys.argv[1],int(sys.argv[2])),Handler).serve_forever()
"""
CLIENT = """import http.client,json,sys
c=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=2,source_address=(sys.argv[3],0))
try:
 c.request('GET','/isolated-nat-check');r=c.getresponse();print(json.dumps({'status':r.status,'body':json.loads(r.read())}))
except OSError as e:print(json.dumps({'error_type':type(e).__name__}))
finally:c.close()
"""


def validate(snapshot, helper=None, filter_rules=None):
    candidate = {}  # Refuse unexpected source topology first.
    assert os.geteuid() == 0, 'root_required_for_disposable_namespaces'
    for binary in ('ip', 'nft', 'python3', 'sysctl'):
        assert shutil.which(binary), 'missing_existing_tool_' + binary
    token = uuid.uuid4().hex[:8]
    names = {role: 'cg26-' + token + '-' + role for role in ('gw', 'ext', 'lan')}
    links = ['cg' + token + suffix for suffix in ('a', 'b', 'c', 'd')]
    created, servers, phases = [], [], []
    owned_links = set()
    before = host_policy_fingerprint()
    full_policy = helper is not None and filter_rules is not None
    result = {'schema': 1, 'scope': 'isolated_NAT_with_host_filter_and_TTL' if full_policy else 'isolated_three_rule_NAT_parity_only',
              'host_nft_apply': False, 'phases': phases, 'namespaces': names}
    outbound_host, outbound_port = ('211.170.162.110', 11434) if full_policy else ('192.168.16.231', 19080)
    ttl_initial = None
    preserved_handles = None

    def inside(role, args, **kwargs):
        assert role in names and names[role] in created, 'namespace_not_owned'
        return command(['ip', 'netns', 'exec', names[role]] + args, **kwargs)

    def nft(transaction):
        return inside('gw', ['nft', '-j', '-f', '-'], data=json.dumps({'nftables': transaction}))

    def connect(role, host, port, source):
        return json.loads(inside(role, ['python3', '-B', '-c', CLIENT, host, str(port), source]).stdout)

    def flows(label):
        inbound = connect('ext', '192.168.16.230', 10443, '192.168.16.231')
        outbound = connect('lan', outbound_host, outbound_port, '10.200.10.10')
        denied = connect('ext', '192.168.16.230', 10443, '192.168.16.200')
        assert inbound.get('status') == 200 and inbound['body']['peer'] == '10.200.10.1', inbound
        assert outbound.get('status') == 200 and outbound['body']['peer'] == '192.168.16.230', outbound
        assert denied.get('error_type') in ('ConnectionRefusedError', 'TimeoutError'), denied
        phase = {'name': label, 'dnat_and_return_masquerade': inbound,
                       'outbound_masquerade': outbound,
                       'outside_source_range_not_forwarded': denied, 'passed': True}
        if full_policy:
            blocked = {'not_retested':'NAT source restriction makes this flow independently ineligible'}
            current = json.loads(inside('gw', ['nft', '-j', 'list', 'table', 'inet', 'capstone_fw']).stdout)
            handles = [(k, o.get('name'), o.get('chain'), o.get('handle'))
                       for k, o in objects(current) if k in ('table', 'chain', 'set') and
                       o.get('name') not in ('nat_prerouting', 'nat_postrouting')]
            element = next(e['elem'] for k, o in objects(current) if k == 'set' and o.get('name') == 'agent_block'
                           for e in o.get('elem', []) if isinstance(e, dict) and e.get('elem', {}).get('val') == '192.168.16.60')
            assert handles == preserved_handles, 'host_policy_or_block_set_recreated'
            assert 0 < element['expires'] <= ttl_initial, element
            assert element.get('comment') == 'capstone-isolated-ttl', element
            phase.update(blocked_source=blocked, block_remaining_native=element['expires'],
                         filter_and_set_handles_preserved=True)
        phases.append(phase)

    def helper_action(action):
        return json.loads(inside('gw', ['python3', '-I', '-B', str(helper), action]).stdout)

    try:
        for name in names.values():
            command(['ip', 'netns', 'add', name]); created.append(name)
        for role in names:
            inside(role, ['ip', 'link', 'set', 'lo', 'up'])
        for a, b, role, interface, address in (
                (links[0], links[1], 'ext', 'ens192', '192.168.16.230/24'),
                (links[2], links[3], 'lan', 'ens160', '10.200.10.1/24')):
            command(['ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b])
            owned_links.update((a, b))
            command(['ip', 'link', 'set', a, 'netns', names['gw']])
            command(['ip', 'link', 'set', b, 'netns', names[role]])
            inside('gw', ['ip', 'link', 'set', a, 'name', interface])
            inside('gw', ['ip', 'addr', 'add', address, 'dev', interface])
            inside('gw', ['ip', 'link', 'set', interface, 'up'])
            inside(role, ['ip', 'link', 'set', b, 'name', 'eth0'])
            inside(role, ['ip', 'link', 'set', 'eth0', 'up'])
        for role, address in (('ext', '192.168.16.231/24'), ('ext', '192.168.16.200/24'),
                              ('lan', '10.200.10.10/24')):
            inside(role, ['ip', 'addr', 'add', address, 'dev', 'eth0'])
        if full_policy:
            inside('ext', ['ip', 'addr', 'add', '192.168.16.60/24', 'dev', 'eth0'])
            inside('ext', ['ip', 'addr', 'add', outbound_host + '/32', 'dev', 'eth0'])
            inside('gw', ['ip', 'route', 'add', outbound_host + '/32', 'via', '192.168.16.231'])
        inside('lan', ['ip', 'route', 'add', 'default', 'via', '10.200.10.1'])
        inside('gw', ['sysctl', '-qw', 'net.ipv4.ip_forward=1'])
        for role, host, port in (('lan', '10.200.10.10', 443), ('ext', outbound_host, outbound_port)):
            servers.append(subprocess.Popen(
                ['ip', 'netns', 'exec', names[role], 'python3', '-B', '-c', SERVER, host, str(port)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # Readiness is checked with real in-namespace sockets; no fixed long sleep.
        deadline = time.monotonic() + 5
        for role, host, port in (('lan', '10.200.10.10', 443), ('ext', outbound_host, outbound_port)):
            while connect(role, host, port, host).get('status') != 200:
                assert time.monotonic() < deadline, 'isolated_http_listener_not_ready'
                time.sleep(.05)
        old = legacy_commands(snapshot)
        host_policy = [{'table': {'family': 'inet', 'name': 'capstone_fw'}}]
        if full_policy:
            host_policy = []
            for kind, obj in objects(snapshot):
                if obj.get('family') != 'inet' or (obj.get('name') if kind == 'table' else obj.get('table')) != 'capstone_fw':
                    continue
                clean = {k: copy.deepcopy(v) for k, v in obj.items() if k not in ('handle', 'index')}
                if kind == 'set' and 'timeout' in obj.get('flags', []) or kind == 'set' and 'dynamic' in obj.get('flags', []):
                    clean.pop('elem', None)
                host_policy.append({kind: clean})
            inside('gw', ['iptables-restore'], data=filter_rules)
        nft([{'add': row} for row in host_policy] + old)
        if full_policy:
            inside('gw', ['nft', '-f', '-'], data='add element inet capstone_fw agent_block { 192.168.16.60 timeout 60s comment "capstone-isolated-ttl" }\n')
            current = json.loads(inside('gw', ['nft', '-j', 'list', 'table', 'inet', 'capstone_fw']).stdout)
            preserved_handles = [(k, o.get('name'), o.get('chain'), o.get('handle'))
                for k, o in objects(current) if k in ('table', 'chain', 'set')]
            ttl_initial = next(e['elem']['expires'] for k, o in objects(current) if k == 'set' and o.get('name') == 'agent_block'
                               for e in o.get('elem', []) if isinstance(e, dict))
        # Model the existing Docker compatibility NAT table before migration.
        # No Docker daemon is started in the disposable network namespace.
        inside('gw', ['iptables','-t','nat','-N','DOCKER'])
        inside('gw', ['iptables','-t','nat','-A','PREROUTING','-m','addrtype','--dst-type','LOCAL','-j','DOCKER'])
        inside('gw', ['iptables','-t','nat','-A','POSTROUTING','-m','comment','--comment','fixture-preserved-counter'])
        flows('legacy')
        if helper:
            result['helper_check'] = helper_action('check')
            result['helper_apply'] = helper_action('apply')
            result['helper_repeat'] = helper_action('apply')
            assert result['helper_repeat']['changed'] is False, 'repeat_rewrote_nat'
        else:
            nft(candidate['transaction']['nftables'])
        flows('merged')
        result['helper_rollback'] = helper_action('undo')
        flows('restored_legacy')
        if helper:
            nft([{'delete': {'table': {'family': 'ip', 'name': name}}} for name in ('capstone_gw', 'capstone_fwd')])
            result['helper_boot_absent'] = helper_action('apply')
            flows('boot_nat_absent')
        if full_policy:
            remaining = [p['block_remaining_native'] for p in phases]
            assert all(a > b for a, b in zip([ttl_initial] + remaining, remaining)), 'block_TTL_reset_or_extended'
            result['temporary_block_deadline_not_extended'] = True
        result['status'] = 'passed'
    finally:
        for process in servers:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        for name in reversed(created):
            command(['ip', 'netns', 'delete', name], check=False)
        for name in owned_links:
            if command(['ip', 'link', 'show', name], check=False).returncode == 0:
                command(['ip', 'link', 'delete', name])
        remaining = {line.split()[0] for line in command(['ip', 'netns', 'list']).stdout.splitlines()}
        result['cleanup_complete'] = not remaining.intersection(created)
        result['host_policy_structure_unchanged'] = before == host_policy_fingerprint()
        assert result['cleanup_complete'], 'namespace_cleanup_failed'
        assert result['host_policy_structure_unchanged'], 'host_policy_changed_during_test'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--consolidated-helper', type=Path)
    parser.add_argument('--iptables-filter', type=Path)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise TimeoutError('isolated_validation_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    print(json.dumps(validate(json.loads(args.snapshot.read_text()), args.consolidated_helper,
                              args.iptables_filter.read_text() if args.iptables_filter else None), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
