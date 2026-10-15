#!/usr/bin/env python3
"""Build/check an operator-reviewed native monitor candidate; never contact a server."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE_SHA256 = 'f0262be494e605edcb22fb32f71f4854014dd4f671b035803886a5b1036bafd1'
DECISIONS = {
    'observation_match': "// Decision: observation_match. Metadata observation, never containment.\ntry {\n    return observationAvailable(ctx) && ctx.results[0].aggregations.observation.value.match;\n} catch (Exception e) {\n    return false;\n}\n",
    'observation_unavailable': "// Decision: observation_unavailable. An empty result is not ingestion health.\ntry {\n    return !observationAvailable(ctx);\n} catch (Exception e) {\n    return true;\n}\n",
}


def artifacts():
    raw = (ROOT.parent / 'monitor.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASE_SHA256:
        raise ValueError('historical_base_sha_changed')
    monitor = json.loads(raw)
    assert monitor['name'] == 'capstone-evidence-observation-v1'
    monitor['enabled'] = False
    search = monitor['inputs'][0]['search']['query']
    filters = search['query']['bool']['filter']
    ranges = [row for row in filters if 'range' in row]
    assert ranges == [{'range': {'timestamp': {'gte': 'now-120s', 'lte': 'now'}}}]
    ranges[0]['range']['timestamp'] = {'gte': 'now-360s', 'lte': 'now+5s'}
    script = next(row['script']['script'] for row in filters if 'script' in row)
    script['source'] = (ROOT / 'monitor-query.painless').read_text()
    search['aggs'] = {'observation': {'scripted_metric': {
        'params': {'period_end': '{{period_end}}'},
        **{stage + '_script': {'lang': 'painless', 'source': (ROOT / ('metric-' + stage + '.painless')).read_text()}
           for stage in ('init', 'map', 'combine', 'reduce')},
    }}}
    common = (ROOT / 'trigger-common.painless').read_text()
    outputs = {}
    for row in monitor['triggers']:
        trigger = row['query_level_trigger']
        assert trigger['actions'] == []
        source = common + '\n' + DECISIONS[trigger['name']]
        trigger['condition']['script'] = {'lang': 'painless', 'source': source}
        filename = 'monitor-match.painless' if trigger['name'] == 'observation_match' else 'monitor-unavailable.painless'
        outputs[filename] = source
    outputs['monitor.json'] = json.dumps(monitor, ensure_ascii=False, indent=2) + '\n'
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs = artifacts()
    for name, source in outputs.items():
        path = ROOT / name
        if args.write:
            path.write_text(source)
        elif not path.exists() or path.read_text() != source:
            raise SystemExit('generated_artifact_mismatch:' + name)
    print(json.dumps({'mode': 'write' if args.write else 'check', 'artifacts': {
        name: {'bytes': len(source.encode()), 'sha256': hashlib.sha256(source.encode()).hexdigest()}
        for name, source in outputs.items()}, 'server_calls': 0}))


if __name__ == '__main__':
    main()
