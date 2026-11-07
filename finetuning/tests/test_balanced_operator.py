import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_balanced_operator import POLICY, canonical, selection


def row(identifier, source, group, oracle=None):
    return {'id': identifier, 'source': source, 'provenance': {'split_group': group,
        'provider_target': oracle or {'rule_id': identifier}}, 'messages': [{'role': 'assistant', 'content': '{}'}]}


class BalancedTests(unittest.TestCase):
    def test_dominant_family_is_capped_without_losing_other_families_or_tools(self):
        rows = [row('crs-'+str(i), 'crs', 'initialization', {'expected': i % 2}) for i in range(60)]
        rows += [row('small', 'crs', 'rare'), row('workflow', 'project_live_mcp', 'live')]
        original = copy.deepcopy(rows); selected = selection(rows)
        self.assertEqual(len(selected), POLICY['crs_per_family']+2)
        self.assertIn('workflow', {r['id'] for r in selected}); self.assertIn('small', {r['id'] for r in selected})
        self.assertEqual(rows, original)
        self.assertEqual({canonical(r) for r in selected}, {canonical(r) for r in selection(list(reversed(rows)))})
        self.assertEqual({r['provenance']['provider_target']['expected'] for r in selected if r['id'].startswith('crs-')}, {0, 1})

    def test_guide_limits_labels_and_shared_organizations_without_rewriting_targets(self):
        rows = []
        for label in ('TruePositive', 'FalsePositive', 'BenignPositive'):
            for i in range(12):
                r = row(label+str(i), 'microsoft-guide-v2-retrospective-triage', 'org-'+str(i))
                r['messages'][-1]['content'] = json.dumps({'classification': label}); rows.append(r)
        selected = selection(rows, {**POLICY, 'guide_per_label': 2})
        self.assertEqual(len(selected), 6)
        self.assertEqual(len({r['provenance']['split_group'] for r in selected}), 6)
        for label in ('TruePositive', 'FalsePositive', 'BenignPositive'):
            self.assertEqual(sum(json.loads(r['messages'][-1]['content'])['classification'] == label for r in selected), 2)

    def test_missing_family_or_provider_oracle_fails_closed(self):
        bad = row('a', 'wazuh', None)
        with self.assertRaises(ValueError): selection([bad])
        bad['provenance'] = {'split_group': 'group'}
        with self.assertRaises(ValueError): selection([bad])


if __name__ == '__main__': unittest.main()
