#!/usr/bin/env python3
"""Pure mock replay of the frozen fractional clock boundary; no host access."""
import argparse
import hashlib
import json
from pathlib import Path
import types
from unittest.mock import patch


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True)
    args=parser.parse_args();here=Path(__file__).resolve().parent
    frozen=json.loads((here/'validation.json').read_text())['clock_boundary']
    source=args.candidate/'infra/mcp/diagnostic_history.py'
    assert source.is_file() and not source.is_symlink()
    assert hashlib.sha256(source.read_bytes()).hexdigest()==frozen['source_sha256']
    h=types.ModuleType('frozen_clock_boundary');h.__file__=str(source)
    exec(compile(source.read_bytes(),str(source),'exec'),h.__dict__)
    def need(condition,reason):
        if not condition:raise ValueError(reason)
    h.core=types.SimpleNamespace(need=need,DiagnosticError=ValueError,TARGETS={'b:vector':'vector.service'})
    rows=[]
    for case in frozen['cases']:
        with patch.object(h.time,'time',return_value=1794750000.75):
            try:h.request(case['arguments']);observed='accepted';reason=None
            except ValueError as exc:observed='rejected';reason=str(exc)
        assert observed==case['observed'] and reason==case['reason']
        rows.append({'id':case['id'],'expected':case['expected_at_microsecond_resolution'],
            'observed':observed,'reason':reason})
    print(json.dumps({'cases':rows,'scope':'Pure validation/clock mock; existing defect reproduced, not corrected',
        'api_calls':0,'operating_changes':0},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
