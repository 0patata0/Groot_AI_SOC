"""Temporary, fail-closed fence for the existing B MCP forced-command wrapper.

The operator keeps Wazuh/diagnostic/event routes byte-for-byte after this guard;
no commands, paths, environment or SSH configuration are accepted from a model.
The persistent marker belongs to the coordinator, never this read-only check.
"""
import hashlib
import re
import shlex

MARKER='/etc/mcp/system-diagnostics/release-fenced'
GATE_PY='''import os,sys
try:
    os.lstat('/etc/mcp/system-diagnostics/release-fenced')
except FileNotFoundError:
    pass
except OSError:
    raise SystemExit(75)
else:
    raise SystemExit(75)
'''


def build(original,expected_sha256):
    if not isinstance(original,bytes)or not 0<len(original)<=32768 or hashlib.sha256(original).hexdigest()!=expected_sha256:
        raise ValueError('mcp_launcher_source_changed')
    text=original.decode('utf-8');matches=list(re.finditer(r'(?m)^set -euo pipefail\n',text))
    if len(matches)!=1 or not text.startswith('#!/bin/bash\n'):
        raise ValueError('mcp_launcher_shape')
    at=matches[0].end()
    guard=('/usr/bin/python3 -I -B -c '+shlex.quote(GATE_PY)+'\n')
    return (text[:at]+guard+text[at:]).encode()
