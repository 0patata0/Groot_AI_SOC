#!/usr/bin/python3 -IB
"""Root-owned response MCP entrypoint; the SSH identity cannot supply secrets."""
import json
import os
from pathlib import Path
import runpy
import resource
import stat
import sys
import urllib.request

ROOT = Path('/opt/capstone-soc')


def trusted(path, private=False):
    for p in (path, *path.parents):
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('response_untrusted_path')
    if private and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError('response_private_configuration')
    return path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('response_redirect_refused')


def set_limits():
    for kind, limit in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_AS, 512 * 1024 * 1024),
                        (resource.RLIMIT_NOFILE, 128), (resource.RLIMIT_CPU, 120)):
        resource.setrlimit(kind, (limit, limit))


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError('response_fixed_root_entrypoint_required')
    set_limits()
    config = json.loads(trusted(ROOT / 'response.json', private=True).read_bytes())
    fields = {'RESP_BROKER_URL', 'RESP_BROKER_TOKEN', 'RESP_MAX_MINUTES', 'RESP_DEFAULT_MINUTES',
              'RESP_APPROVAL_TIMEOUT', 'RESP_APPROVAL_POLL', 'RESP_NOTIFY_BACKEND', 'RESP_NOTIFY_URL'}
    if (not isinstance(config, dict) or set(config) - fields or
            config.get('RESP_BROKER_URL') != 'https://10.200.10.10:8445' or
            len(config.get('RESP_BROKER_TOKEN', '')) < 32 or
            any(not isinstance(v, str) or '\n' in v or '\0' in v for v in config.values())):
        raise ValueError('response_configuration_refused')
    os.environ.clear()
    os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', PYTHONDONTWRITEBYTECODE='1')
    os.environ.update(config)
    os.environ['RESP_AGENT_BLOCK'] = '/usr/local/libexec/capstone-response-apply'
    trusted(Path(os.environ['RESP_AGENT_BLOCK']))
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()))
    if (ROOT / 'notifier.py').exists():
        namespace = runpy.run_path(str(trusted(ROOT / 'notifier.py')))
        import types
        notifier = types.ModuleType('notifier')
        notifier.__dict__.update(namespace)
        sys.modules['notifier'] = notifier
    runpy.run_path(str(trusted(ROOT / 'response-mcp.py')), run_name='__main__')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('response entrypoint refused', file=sys.stderr)
        raise SystemExit(77)
