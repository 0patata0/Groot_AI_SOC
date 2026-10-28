"""Group source observations by related actors and cited documents before sampling."""
import hashlib
import re
from urllib.parse import urlsplit, unquote


class Groups:
    def __init__(self):
        self.parent = {}

    def find(self, item):
        self.parent.setdefault(item, item)
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def join(self, *items):
        if not items:
            raise ValueError('Empty evidence group')
        for item in items[1:]:
            a, b = self.find(items[0]), self.find(item)
            self.parent[max(a, b)] = min(a, b)
        self.find(items[0])

    def identities(self):
        members = {}
        for item in sorted(self.parent):
            members.setdefault(self.find(item), []).append(item)
        return {item: hashlib.sha256('\n'.join(members[self.find(item)]).encode()).hexdigest()
                for item in self.parent}


def report_key(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Invalid public source URL')
    # CISA advisory IDs survive URL/attachment/version changes. URL decoding
    # handles report IDs in older escaped attachment paths.
    advisory = re.search(r'aa\d{2}-\d{3}[a-z](?![a-z0-9])', unquote(url), re.I)
    if advisory and (parsed.hostname.endswith(('.cisa.gov', '.us-cert.gov')) or
                     parsed.hostname in ('cisa.gov', 'us-cert.gov')):
        return 'cisa:' + advisory[0].upper()
    host = parsed.hostname.lower().removeprefix('www.')
    path = unquote(parsed.path).rstrip('/')
    # Tracking parameters/fragments do not define separate reports.
    return 'url:' + host + path


def related_groups(objects, relationships, cisa_ids):
    groups = Groups()
    lookup = {o['id']: o for o in objects}
    external = {r['external_id']: o['id'] for o in objects
                if o['type'] in ('intrusion-set', 'campaign')
                for r in o.get('external_references', [])
                if r.get('source_name') == 'mitre-attack' and r.get('external_id')}
    for row in relationships:
        nodes = ['entity:' + row['source_ref']]
        nodes += [report_key(r['url']) for r in row.get('external_references', []) if r.get('url')]
        for identifier in re.findall(r'https?://attack\.mitre\.org/(?:groups|campaigns)/([GC]\d+)', row['description']):
            if identifier in external:
                nodes.append('entity:' + external[identifier])
        groups.join(*nodes)
    for row in objects:
        if row['type'] == 'relationship' and row.get('relationship_type') == 'attributed-to':
            a, b = lookup.get(row.get('source_ref'), {}), lookup.get(row.get('target_ref'), {})
            if a.get('type') == 'campaign' and b.get('type') == 'intrusion-set':
                groups.join('entity:' + a['id'], 'entity:' + b['id'])
    for identifier in cisa_ids:
        groups.find('cisa:' + identifier)
    return groups.identities()


def split_group(group, forced):
    if group in forced:
        return forced[group]
    bucket = int(hashlib.sha256(('soc-evidence-v5:' + group).encode()).hexdigest()[:8], 16) % 10
    return 'validation' if bucket == 0 else 'test' if bucket == 1 else 'train'
