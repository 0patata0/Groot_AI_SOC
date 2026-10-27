#!/usr/bin/env python3
"""Read-only corpus audit against an observed MCP schema snapshot; never rename tools."""
import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path

from prepare_data import check_schema, matches_schema, Reject


def supported(schema):
    allowed = {'type','properties','required','additionalProperties','items','enum','const',
               'allOf','anyOf','oneOf','minLength','maxLength','pattern','minItems','maxItems',
               'uniqueItems','minProperties','maxProperties','minimum','maximum',
               'exclusiveMinimum','exclusiveMaximum','multipleOf','title','description',
               'default','examples','$schema','$id','deprecated','readOnly','writeOnly'}
    if not isinstance(schema, dict) or set(schema) - allowed:
        return False
    children = list(schema.get('properties', {}).values())
    for key in ('items','additionalProperties'):
        if isinstance(schema.get(key), dict): children.append(schema[key])
    for key in ('allOf','anyOf','oneOf'): children.extend(schema.get(key, []))
    return all(supported(child) for child in children)


def audit_rows(rows, catalog):
    counts, unknown = Counter(), Counter()
    entries = catalog['tools']
    tools = {t['name']: t for t in entries}
    if len(tools) != len(entries): raise ValueError('Duplicate catalog tool names')
    for row in rows:
        counts['rows'] += 1
        calls = [call for message in row['messages'] if message['role'] == 'assistant'
                 for call in message.get('tool_calls', [])]
        if not calls:
            counts['rows_without_structured_calls'] += 1
            continue
        counts['rows_with_calls'] += 1
        valid = True
        for call in calls:
            counts['calls'] += 1
            fn = call.get('function', call); name = fn.get('name'); entry = tools.get(name)
            if not entry:
                counts['unknown_tool_calls'] += 1; unknown[str(name)] += 1; valid = False
                continue
            counts['current_named_calls'] += 1
            if entry['protected']: counts['protected_named_calls_requiring_policy_review'] += 1
            schema = copy.deepcopy(entry['parameters'])
            try:
                if not supported(schema): raise Reject('unsupported_schema_constraint')
                check_schema(schema, root=True)
                arguments = fn.get('arguments')
                if isinstance(arguments, str): arguments = json.loads(arguments)
                if not matches_schema(arguments, schema): raise Reject('arguments_schema_mismatch')
                counts['schema_valid_calls'] += 1
            except (Reject, ValueError, TypeError):
                counts['invalid_or_unchecked_calls'] += 1; valid = False
        if valid: counts['rows_with_current_names_and_valid_arguments'] += 1
    return {'counts': dict(counts), 'unknown_tool_names': dict(sorted(unknown.items())),
            'policy_and_answer_accuracy_reviewed': False,
            'note': 'Schema compatibility only. No tool executed, renamed, approved, or judged semantically correct.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--catalog', type=Path, default=Path(__file__).with_name('mcp_contract.json'))
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text())
    with args.data.open() as handle: result = audit_rows((json.loads(line) for line in handle), catalog)
    result.update(catalog_observed_at_kst=catalog['observed_at_kst'],
                  catalog_sha256=hashlib.sha256(args.catalog.read_bytes()).hexdigest())
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
