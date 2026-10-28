"""Add hierarchy/context diagnostics without rewriting original generated answers.

Reference-label disagreement is not proof that every alternative interpretation
is technically false. Parent-only predictions still omit requested specificity.
"""
import argparse
import json
from pathlib import Path


def review(report):
    parents, non_reference = 0, 0
    cases = []
    for result in report['results']:
        metrics = result['assessment']
        missing = metrics['missing_IDs']; predicted_extra = metrics['unsupported_IDs']
        parent_pairs = [{'expected': wanted, 'predicted_parent': candidate} for wanted in missing
                        for candidate in predicted_extra if wanted.startswith(candidate + '.')]
        parents += len({p['expected'] for p in parent_pairs})
        # Recall times label count is not rounded/reconstructed here. The
        # hierarchy diagnostic reports counts of omitted child labels only.
        non_reference += len(predicted_extra)
        cases.append({'case_id': result['case_id'], 'parent_instead_of_child': parent_pairs,
                      'non_reference_prediction_IDs': predicted_extra,
                      'scope': 'not all non-reference predictions are proven false; provider labels may be non-exhaustive'})
    return {'reference_metrics': report.get('summary'), 'omitted_children_with_predicted_parent': parents,
            'non_reference_prediction_IDs': non_reference, 'cases': cases,
            'interpretation': 'Exact source agreement and canonical-format completeness are distinct from semantic incident correctness. Parent predictions are coarser, not automatically unrelated hallucinations. Independent semantic review remains necessary.',
            'raw_generation_preserved': True, 'actual_MCP_tools_executed': False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise ValueError('Preserve prior assessment')
    a.output.write_text(json.dumps(review(json.loads(a.input.read_text())),ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':main()
