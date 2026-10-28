"""Extract only explicitly configured CISA ATT&CK tables from pdftotext layouts.

Each row retains its original page, table, text and ID. Unparsed table IDs are
reported, never silently discarded or replaced with model-written labels.
"""
import hashlib
import re

ID = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
TABLE = re.compile(r'\bTable\s+(\d+):\s*(.+)')
TACTICS = {'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
           'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
           'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
           'Exfiltration', 'Impact'}


def clean(text):
    return ' '.join(text.replace('\u00ad', '').split())


def extract(layout, spec):
    rows, rejected = [], []
    current_table = None
    previous = None
    encountered = []
    for page_number, page in enumerate(layout.split('\f'), 1):
        if not spec['first_page'] <= page_number <= spec['last_page']:
            continue
        blocks, block = [], []
        for line_number, line in enumerate(page.splitlines(), 1):
            title = TABLE.search(line)
            if title:
                if block:
                    blocks.append(block); block = []
                number = int(title[1])
                current_table = number if number in spec['tables'] else None
                previous = None
                continue
            if current_table is None:
                continue
            stripped = line.strip()
            if stripped.startswith(('Detection Methods', 'MITIGATIONS', 'Mitigations', 'ACKNOWLEDGEMENTS')):
                if block:
                    blocks.append(block); block = []
                current_table = None
                continue
            if not stripped:
                if block:
                    blocks.append(block); block = []
                continue
            if (stripped.startswith(('Page ', 'TLP:CLEAR')) or ' | CISA' in stripped or
                re.fullmatch(r'(?:FBI|CISA|HHS|MS-ISAC|\s|\|)+', stripped) or
                ('Technique Title' in line and re.search(r'\bID\b', line))):
                continue
            if stripped in TACTICS and len(line) - len(line.lstrip()) >= 30:
                continue
            block.append((line_number, line, current_table))
        if block:
            blocks.append(block)
        for block in blocks:
            found = [(n, line, m) for n, line, _ in block for m in ID.finditer(line)]
            # Body text may mention an ID; only the middle ID column defines a
            # table row. Other occurrences remain evidence text.
            central = [(n, line, m) for n, line, m in found if 27 <= m.start() <= 58]
            encountered.extend((page_number, n, m[0]) for n, _, m in central)
            if not central:
                if (previous and block[0][2] == previous['table'] and
                    all(not line[:previous['title_cut']].strip() for _, line, _ in block)):
                    extra = clean(' '.join(line[previous['description_cut']:] for _, line, _ in block))
                    if extra:
                        previous['description'] += ' ' + extra
                        previous['raw_lines'] += block
                continue
            if len(central) != 1:
                rejected.append({'page': page_number, 'reason': 'ambiguous_ID_block',
                                 'ids': [m[0] for _, _, m in central]})
                previous = None
                continue
            _, _, match = central[0]
            title_cut, description_cut = match.start(), match.end()
            title = clean(' '.join(line[:title_cut] for _, line, _ in block))
            description = clean(' '.join(line[description_cut:] for _, line, _ in block))
            title = re.sub(r'\(New [^)]+\)\s*', '', title).strip()
            if not title or len(description) < 20 or ID.search(title):
                rejected.append({'page': page_number, 'reason': 'empty_or_ambiguous_cells', 'ids': [match[0]]})
                previous = None
                continue
            previous = {'page': page_number, 'table': block[0][2], 'technique_id': match[0],
                        'title': title, 'description': description, 'title_cut': title_cut,
                        'description_cut': description_cut, 'raw_lines': block}
            rows.append(previous)
    for row in rows:
        raw = '\n'.join(line for _, line, _ in row.pop('raw_lines'))
        row['raw_row_text'] = raw
        row['raw_row_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
        row.pop('title_cut'); row.pop('description_cut')
    if len(rows) + sum(len(r['ids']) for r in rejected) != len(encountered):
        raise ValueError('CISA ID accounting mismatch')
    return rows, {'encountered_table_IDs': len(encountered), 'parsed_rows': len(rows), 'rejected': rejected}
