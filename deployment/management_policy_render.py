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


def source_text(raw):
    """The trusted caller supplies bytes, never a model-selected file path."""
    if not isinstance(raw, bytes) or len(raw) > 4 * 1024 * 1024 or b'\0' in raw or b'\r' in raw:
        raise ValueError('management_source_bytes')
    return raw.decode('utf-8')


LEX = re.compile(r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};,]|[^\s{};,\#"']+''')


def source_tokens(text):
    result = []
    position = 0
    for match in LEX.finditer(text):
        if match.start() != position:
            raise ValueError('management_source_token')
        value = match[0]
        if not value.isspace() and not value.startswith('#'):
            result.append((value, match.start(), match.end()))
        position = match.end()
    if position != len(text):
        raise ValueError('management_source_token')
    return result


def braces(tokens):
    stack, pairs = [], {}
    for index, (value, _, _) in enumerate(tokens):
        if value == '{':
            stack.append(index)
            if len(stack) > 64:
                raise ValueError('management_source_depth')
        elif value == '}':
            if not stack:
                raise ValueError('management_source_braces')
            pairs[stack.pop()] = index
    if stack:
        raise ValueError('management_source_braces')
    return pairs


def exact_block(tokens, pairs, prefix, lower=0, upper=None):
    upper = len(tokens) if upper is None else upper
    found = []
    index = lower
    while index < upper:
        if [t[0] for t in tokens[index:index + len(prefix)]] == list(prefix):
            opening = index + len(prefix) - 1
            if tokens[opening][0] != '{' or opening not in pairs:
                raise ValueError('management_source_block')
            found.append((opening, pairs[opening]))
        # Only direct blocks of the selected parent are candidates.
        if tokens[index][0] == '{':
            index = pairs[index]
        index += 1
    if len(found) != 1:
        raise ValueError('management_source_unique_block')
    return found[0]


def protection_addresses(values):
    """An existing infrastructure exemption is distinct from an administrator."""
    import ipaddress
    if not isinstance(values, list) or len(values) > 1024:
        raise ValueError('management_protection_addresses')
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError('management_protection_address')
        network = ipaddress.IPv4Network(value, strict=True)
        if not network.prefixlen or network.is_multicast:
            raise ValueError('management_protection_address')
        result.append(network)
    if len(set(result)) != len(result):
        raise ValueError('management_duplicate_protection')
    return [str(x) for x in sorted(result)]


def firewall_sets(raw):
    """Parse only the two fixed static sets; dynamic block sets are untouched."""
    text = source_text(raw)
    tokens = source_tokens(text)
    pairs = braces(tokens)
    table = exact_block(tokens, pairs, ('table', 'inet', 'capstone_fw', '{'))
    result = {}
    for name in ('mgmt_src', 'never_block'):
        start, end = exact_block(tokens, pairs, ('set', name, '{'), table[0] + 1, table[1])
        body = tokens[start + 1:end]
        if [t[0] for t in body[:2]] != ['type', 'ipv4_addr']:
            raise ValueError('management_firewall_set_type')
        matches = [i for i in range(start + 1, end) if tokens[i][0] == 'elements']
        if len(matches) != 1:
            raise ValueError('management_firewall_elements')
        opening = matches[0] + 2
        if [t[0] for t in tokens[matches[0]:opening + 1]] != ['elements', '=', '{']:
            raise ValueError('management_firewall_elements')
        closing = pairs[opening]
        if closing >= end:
            raise ValueError('management_firewall_elements')
        elements = [t[0] for t in tokens[opening + 1:closing]]
        if not elements or any(value != ',' for value in elements[1::2]) or len(elements) % 2 == 0:
            raise ValueError('management_firewall_elements')
        result[name] = {'cidrs': protection_addresses(elements[::2]),
                        'span': (tokens[opening][2], tokens[closing][1])}
    return result


def firewall(raw, before, desired, infrastructure):
    """Replace administrator ownership only, retaining the approved infrastructure.

    The fixed worker must bind the infrastructure list from its root-owned
    baseline. It must not obtain this list or original file bytes from a model.
    An unknown extra/missing exemption makes this candidate invalid.
    """
    import ipaddress
    old = contract.addresses(before)
    new = contract.addresses(desired)
    retained = protection_addresses(infrastructure)
    if set(retained) & set(old):
        raise ValueError('management_protection_ownership_overlap')
    observed = firewall_sets(raw)
    if observed['mgmt_src']['cidrs'] != old or set(observed['never_block']['cidrs']) != set(retained + old):
        raise ValueError('management_firewall_baseline_changed')
    # Do not collapse these roles together: removing an administrator later
    # must never accidentally remove a shared infrastructure network.
    values = {'mgmt_src': new,
              'never_block': [str(n) for n in sorted(set(map(ipaddress.IPv4Network, retained + new)))]}
    text = source_text(raw)
    replacements = [(observed[name]['span'], ' ' + ', '.join(values[name]) + ' ')
                    for name in values]
    for (start, end), replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    result = text.encode()
    if any(firewall_sets(result)[name]['cidrs'] != values[name] for name in values):
        raise ValueError('management_firewall_candidate')
    return result


def nginx_nodes(tokens, lower=0, upper=None):
    upper = len(tokens) if upper is None else upper
    pairs = braces(tokens)
    result, head, start = [], [], lower
    index = lower
    while index < upper:
        value = tokens[index][0]
        if not head:
            start = index
        if value == '{':
            if not head:
                raise ValueError('management_proxy_syntax')
            closing = pairs[index]
            result.append({'head': head, 'start': tokens[start][1], 'end': tokens[closing][2],
                           'children': nginx_nodes(tokens, index + 1, closing)})
            index = closing
            head = []
        elif value == ';':
            if not head:
                raise ValueError('management_proxy_syntax')
            result.append({'head': head, 'start': tokens[start][1], 'end': tokens[index][2],
                           'children': None})
            head = []
        elif value == '}':
            raise ValueError('management_proxy_syntax')
        else:
            head.append(value)
        index += 1
    if head:
        raise ValueError('management_proxy_syntax')
    return result


WAZUH_NAMES = frozenset(('wazuh.groot.lab', 'wazuh.grootlab.duckdns.org'))


def proxy(raw, before, desired):
    """Touch Wazuh management server ACLs only, never a public lab/attack path."""
    text = source_text(raw)
    nodes = nginx_nodes(source_tokens(text))
    old, new = contract.addresses(before), contract.addresses(desired)
    found, replacements = set(), []

    def visit(items):
        for node in items:
            children = node['children']
            if node['head'] != ['server']:
                if children is not None:
                    visit(children)
                continue
            names = [x for x in children if x['head'][0] == 'server_name']
            selected = [x for x in names if set(x['head'][1:]) & WAZUH_NAMES]
            if not selected:
                continue
            if len(names) != 1 or len(selected[0]['head']) != 2 or selected[0]['head'][1] in found:
                raise ValueError('management_proxy_server_names')
            name = selected[0]['head'][1]
            if name not in WAZUH_NAMES:
                raise ValueError('management_proxy_server_names')
            # An inherited include, satisfy-any or nested ACL could undermine
            # the apparent allow/deny list. Reject it instead of guessing.
            def safe(items, nested=False):
                for child in items:
                    key = child['head'][0]
                    if key in ('include', 'satisfy', 'limit_except') or (nested and key in ('allow', 'deny')):
                        raise ValueError('management_proxy_acl_override')
                    if child['children'] is not None:
                        safe(child['children'], True)
            safe(children)
            acl = [x for x in children if x['head'][0] in ('allow', 'deny')]
            if (not acl or acl[-1]['head'] != ['deny', 'all'] or
                    any(x['children'] is not None or len(x['head']) != 2 or x['head'][0] != 'allow' for x in acl[:-1])):
                raise ValueError('management_proxy_acl_order')
            if contract.addresses([x['head'][1] for x in acl[:-1]]) != old:
                raise ValueError('management_proxy_baseline_changed')
            first = acl[0]
            indent = text[text.rfind('\n', 0, first['start']) + 1:first['start']]
            if indent.strip():
                raise ValueError('management_proxy_acl_layout')
            # Only complete allow directives and intervening whitespace/comments
            # can be replaced; all TLS/proxy/public-service bytes stay intact.
            for left, right in zip(acl[:-1], acl[1:]):
                if source_tokens(text[left['end']:right['start']]):
                    raise ValueError('management_proxy_acl_not_contiguous')
            replacement = ('\n' + indent).join('allow ' + value + ';' for value in new) + '\n' + indent
            replacements.append((first['start'], acl[-1]['start'], replacement))
            found.add(name)
    visit(nodes)
    if found != WAZUH_NAMES:
        raise ValueError('management_proxy_required_servers')
    for start, end, replacement in sorted(replacements, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text.encode()


THRESHOLD = re.compile(r'^\s*suppress\s+gen_id\s+1\s*,\s*sig_id\s+2001219\s*,\s*track\s+by_src\s*,\s*ip\s+([0-9./]+)\s*(?:#[^\n]*)?$')


def threshold(raw, before, desired):
    """Only the explicit SSH SYN-count heuristic, never all attack signatures."""
    text = source_text(raw)
    lines = text.splitlines(keepends=True)
    selected = [(i, THRESHOLD.fullmatch(line.rstrip('\n'))) for i, line in enumerate(lines)]
    if any(not line.lstrip().startswith('#') and re.search(r'\bsig_id\s+2001219\b', line)
           and match is None for line, (_, match) in zip(lines, selected)):
        raise ValueError('management_threshold_unknown_policy')
    selected = [(i, match) for i, match in selected if match is not None]
    if not selected or contract.addresses([m[1] for _, m in selected]) != contract.addresses(before):
        raise ValueError('management_threshold_baseline_changed')
    values = [m[1] for _, m in selected]
    if len(values) != len(set(values)):
        raise ValueError('management_threshold_duplicate')
    replacement = ''.join('suppress gen_id 1, sig_id 2001219, track by_src, ip ' + value + '\n'
                          for value in contract.addresses(desired))
    first = selected[0][0]
    positions = {i for i, _ in selected}
    return ''.join(replacement if i == first else '' if i in positions else line
                   for i, line in enumerate(lines)).encode()


def lab_environment(raw, desired):
    """Preserve opaque secret assignments; only set the fixed CIDR variable."""
    text = source_text(raw)
    lines = text.splitlines(keepends=True)
    prefix = 'OFFLINE_LABS_ADMIN_CIDRS'
    indices = [i for i, line in enumerate(lines) if re.match(r'\s*(?:export\s+)?' + prefix + r'\b', line)]
    if len(indices) > 1:
        raise ValueError('management_lab_duplicate_assignment')
    replacement = prefix + '=' + ','.join(contract.addresses(desired)) + '\n'
    if indices:
        i = indices[0]
        if not re.fullmatch(prefix + r'=[^\n]*\n?', lines[i]):
            raise ValueError('management_lab_assignment_format')
        lines[i] = replacement
    else:
        if text and not text.endswith('\n'):
            lines.append('\n')
        lines.append(replacement)
    return ''.join(lines).encode()


def host_guard(raw, host, desired):
    """Use the actual gateway source for downstream SSH, not the raw admin IP.

    This updates the existing fixed host-guard configuration only. The worker
    must separately inspect its generated kernel policy and effective sshd
    Match blocks; file generation cannot prove a successful management route.
    """
    import ipaddress
    import json
    spec = importlib.util.spec_from_file_location('_management_host_guard', Path(__file__).with_name('host_security.py'))
    host_security = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_security)
    roles = {'a': 'security', 'b': 'siem', 'c': 'service'}
    if host not in roles:
        raise ValueError('management_host_role')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('management_host_duplicate_field')
            result[key] = value
        return result
    original = json.loads(source_text(raw), object_pairs_hook=unique)
    value = host_security.configuration(original)
    if value['role'] != roles[host]:
        raise ValueError('management_host_role')
    cidrs = contract.addresses(desired)
    effective = cidrs if host == 'a' else [str(ipaddress.IPv4Network(value['security_host'] + '/32'))]
    if value['management_cidrs'] == effective:
        return raw
    # Preserve all other input fields, including distinctions between dashboard,
    # chat, legacy bridge and internal service peers.
    candidate = {**original, 'management_cidrs': effective}
    host_security.configuration(candidate)
    return (json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


WAZUH_BEGIN = '<!-- BEGIN CAPSTONE_MANAGEMENT_WHITELIST -->'
WAZUH_END = '<!-- END CAPSTONE_MANAGEMENT_WHITELIST -->'


def wazuh_global_span(raw):
    """Locate the one whitelist global block, ignoring fake tags in comments.

    Wazuh supports separate global fragments. A unique existing whitelist
    fragment is the anchor; other global settings are preserved byte-for-byte.
    Multiple whitelist fragments need an explicit ownership migration.
    """
    from xml.parsers import expat
    source_text(raw)
    if b'<!DOCTYPE' in raw or b'<!ENTITY' in raw:
        raise ValueError('management_wazuh_external_definition')
    prefix = b'<capstone-fragments>'
    parser = expat.ParserCreate()
    stack, spans = [], []

    def start(name, attributes):
        stack.append(name)
        if name == 'global':
            if attributes or stack[-2:] != ['ossec_config', 'global']:
                raise ValueError('management_wazuh_global_parent')
            begin = parser.CurrentByteIndex - len(prefix)
            finish = raw.index(b'>', begin) + 1
            if raw[begin:finish].rstrip().endswith(b'/>'):
                raise ValueError('management_wazuh_empty_global_syntax')
            spans.append({'lower': finish, 'upper': None, 'whitelist_count': 0})
        elif name == 'white_list' and len(stack) > 1 and stack[-2] == 'global':
            spans[-1]['whitelist_count'] += 1

    def end(name):
        if name == 'global':
            spans[-1]['upper'] = parser.CurrentByteIndex - len(prefix)
        stack.pop()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.ExternalEntityRefHandler = lambda *args: 0
    try:
        parser.Parse(prefix + raw + b'</capstone-fragments>', True)
    except expat.ExpatError:
        raise ValueError('management_wazuh_xml') from None
    selected = [span for span in spans if span['whitelist_count']]
    if not selected and len(spans) == 1:
        selected = spans
    if len(selected) != 1 or selected[0]['upper'] is None:
        raise ValueError('management_wazuh_unique_global')
    return selected[0]['lower'], selected[0]['upper']


def wazuh_whitelist(raw, desired):
    """Own only the explicit management block; retain existing Wazuh safeguards.

    Unmanaged whitelist entries are retained and must be separately reported as
    such by the observer. Their overlap cannot certify removal of an address.
    The raw source and full candidate stay within the fixed root worker.
    """
    import xml.etree.ElementTree as ET
    lower, upper = wazuh_global_span(raw)
    before = raw[:lower]
    body = raw[lower:upper]
    after = raw[upper:]
    begin, end = WAZUH_BEGIN.encode(), WAZUH_END.encode()
    cidrs = contract.addresses(desired)
    generated = (WAZUH_BEGIN + '\n' + ''.join('    <white_list>' + value + '</white_list>\n' for value in cidrs)
                 + '    ' + WAZUH_END).encode()
    if begin in raw or end in raw:
        if raw.count(begin) != 1 or raw.count(end) != 1 or begin not in body or end not in body:
            raise ValueError('management_wazuh_block_scope')
        start = body.index(begin)
        finish = body.index(end)
        if finish < start:
            raise ValueError('management_wazuh_block_order')
        previous = body[start + len(begin):finish]
        root = ET.fromstring(b'<root>' + previous + b'</root>')
        if root.text and root.text.strip() or not list(root):
            raise ValueError('management_wazuh_block_content')
        previous_cidrs = []
        for element in root:
            if (element.tag != 'white_list' or element.attrib or list(element) or
                    element.tail and element.tail.strip()):
                raise ValueError('management_wazuh_block_content')
            previous_cidrs.append(element.text or '')
        if contract.addresses(previous_cidrs) != previous_cidrs:
            raise ValueError('management_wazuh_block_addresses')
        body = body[:start] + generated + body[finish + len(end):]
    else:
        body += b'\n    ' + generated + b'\n  '
    result = before + body + after
    wazuh_global_span(result)
    return result
