"""Regression fixtures for missing evidence, conditional branches and cycles."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_flow_graph import project, redact
from collections import Counter


def fixture():
    nodes = [
        {'id': 'action', 'instance': 'a', 'properties': [['name', 'initial']], 'anchors': {}},
        {'id': 'condition', 'instance': 'c', 'properties': [['description', 'success?']], 'anchors': {}},
        {'id': 'action', 'instance': 'yes', 'properties': [['name', 'success path']], 'anchors': {}},
        {'id': 'action', 'instance': 'no', 'properties': [['name', 'failure path']], 'anchors': {}},
        {'id': 'AND_operator', 'instance': 'and', 'properties': [['operator', 'AND']], 'anchors': {}},
        {'id': 'OR_operator', 'instance': 'or', 'properties': [['operator', 'OR']], 'anchors': {}},
        {'id': 'tool', 'instance': 'tool', 'properties': [['name', 'context']], 'anchors': {}},
    ]
    root = {'id': 'flow', 'instance': 'root', 'properties': [['scope', 'incident']],
            'objects': [o['instance'] for o in nodes]}
    return {'schema': 'attack_flow_v2', 'objects': [root] + nodes, 'layout': {}, 'camera': {}, 'theme': 'dark_theme'}


def edge(doc, source, target, route='0', identifier=None):
    nodes = {o['instance']: o for o in doc['objects']}
    identifier = identifier or 'line-' + str(len(doc['objects']))
    ends = []
    for suffix, inst, position in [('s', source, route), ('t', target, '180')]:
        anchor_id = inst + '-' + position
        if anchor_id not in nodes:
            anchor = {'id': 'vertical_anchor', 'instance': anchor_id, 'latches': []}
            doc['objects'].append(anchor)
            nodes[anchor_id] = anchor
            nodes[inst]['anchors'][position] = anchor_id
        latch_id = identifier + '-' + suffix
        nodes[anchor_id]['latches'].append(latch_id)
        doc['objects'].append({'id': 'generic_latch', 'instance': latch_id})
        ends.append(latch_id)
    line = {'id': 'dynamic_line', 'instance': identifier, 'source': ends[0], 'target': ends[1],
            'handles': [], 'properties': [['confidence', 0]]}
    doc['objects'].append(line)
    doc['objects'][0]['objects'].append(identifier)
    return identifier


class GraphTests(unittest.TestCase):
    def test_true_false_and_or_context_and_edge_confidence_preserved(self):
        d = fixture()
        for args in [('a', 'c'), ('c', 'yes', 'branch:True'), ('c', 'no', 'branch:False'),
                     ('yes', 'and'), ('no', 'or'), ('and', 'a'), ('or', 'a'), ('a', 'tool')]:
            edge(d, *args)
        r = project(d)
        self.assertEqual(r['counts']['relations'], {'effect': 5, 'on_true': 1, 'on_false': 1, 'context_relation': 1})
        self.assertEqual(r['counts']['nodes'], 7)
        self.assertEqual(r['edges'][1]['condition_branch'], 'true')
        self.assertEqual(r['edges'][2]['condition_branch'], 'false')
        self.assertTrue(all(e['properties'] == [['confidence', 0]] for e in r['edges']))
        self.assertFalse(r['interpretation']['ordered_steps'])

    def test_ordinary_condition_anchor_does_not_imply_true(self):
        d = fixture(); identifier = edge(d, 'c', 'yes', '330')
        r = project(d)
        self.assertEqual(r['edges'][0]['relation'], 'context_relation')
        self.assertIsNone(r['edges'][0]['condition_branch'])
        self.assertEqual(r['review_flags']['condition_control_links_without_explicit_branch'], [identifier])

    def test_cycle_self_loop_and_duplicate_endpoint_edges_are_not_dropped(self):
        d = fixture()
        for a, b in [('a', 'yes'), ('yes', 'a'), ('a', 'a'), ('a', 'yes')]: edge(d, a, b)
        r = project(d)
        self.assertEqual(len(r['edges']), 4)
        self.assertEqual(len({e['id'] for e in r['edges']}), 4)
        self.assertEqual(sum(e['source'] == e['target'] for e in r['edges']), 1)

    def test_context_and_disconnected_nodes_not_silently_dropped(self):
        d = fixture(); edge(d, 'a', 'tool')
        r = project(d)
        self.assertEqual({n['id'] for n in r['nodes']}, {'a', 'c', 'yes', 'no', 'and', 'or', 'tool'})

    def test_unresolved_line_fails(self):
        d = fixture(); edge(d, 'a', 'c'); d['objects'][-1]['target'] = 'missing'
        with self.assertRaisesRegex(ValueError, 'Unresolved'): project(d)

    def test_duplicate_object_and_root_member_fail(self):
        d = fixture(); d['objects'].append(deepcopy(d['objects'][1]))
        with self.assertRaisesRegex(ValueError, 'Duplicate'): project(d)
        d = fixture(); d['objects'][0]['objects'].pop()
        with self.assertRaisesRegex(ValueError, 'membership'): project(d)

    def test_unreviewed_object_and_field_fail(self):
        d = fixture(); d['objects'][1]['id'] = 'new_type'
        with self.assertRaisesRegex(ValueError, 'Unreviewed'): project(d)
        d = fixture(); d['objects'][1]['hidden_relation'] = 'yes'
        with self.assertRaisesRegex(ValueError, 'Unreviewed'): project(d)

    def test_operator_value_mismatch_and_unknown_branch_fail(self):
        d = fixture(); d['objects'][5]['properties'] = [['operator', 'OR']]
        with self.assertRaisesRegex(ValueError, 'Operator'): project(d)
        d = fixture(); edge(d, 'c', 'a', 'branch:Maybe')
        with self.assertRaisesRegex(ValueError, 'branch'): project(d)

    def test_duplicate_property_fails_instead_of_overwriting(self):
        d = fixture(); d['objects'][1]['properties'].append(['name', 'overwritten'])
        with self.assertRaisesRegex(ValueError, 'Duplicate property'): project(d)

    def test_shared_anchor_or_latch_fails(self):
        d = fixture(); edge(d, 'a', 'yes'); d['objects'][2]['anchors'] = deepcopy(d['objects'][1]['anchors'])
        with self.assertRaisesRegex(ValueError, 'Repeated anchor'): project(d)
        d = fixture(); edge(d, 'a', 'yes')
        anchor = next(o for o in d['objects'] if o['id'] == 'vertical_anchor')
        anchor['latches'].append(anchor['latches'][0])
        with self.assertRaisesRegex(ValueError, 'Repeated latch'): project(d)

    def test_redact_populated_structured_fields_preserves_false_null_zero(self):
        values = [['author', [['name', 'Source Author'], ['contact_information', 'fixture-contact']]],
                  ['credential', 'fixture-credential'], ['decryption_key', None], ['enabled', False], ['size', 0]]
        original = deepcopy(values); removed = Counter(); result = redact(values, removed)
        self.assertEqual(values, original)
        self.assertEqual(removed, {'contact_information': 1, 'credential': 1})
        self.assertNotIn('fixture-contact', json.dumps(result))
        self.assertNotIn('fixture-credential', json.dumps(result))
        self.assertEqual(result[2:], values[2:])

    def test_reference_metadata_and_no_success_or_time_inference(self):
        d = fixture(); d['objects'][0]['properties'].append(['external_references', [['r', [['url', 'https://example.invalid/source']]]]])
        d['objects'][1]['properties'].extend([['execution_start', None], ['confidence', 'unknown']])
        r = project(d)
        self.assertEqual(r['metadata'], d['objects'][0]['properties'])
        self.assertEqual(r['nodes'][0]['properties'], d['objects'][1]['properties'])
        self.assertFalse(r['interpretation']['source_order_is_chronology'])
        self.assertFalse(r['interpretation']['branches_are_observed_success'])


if __name__ == '__main__':
    unittest.main()
