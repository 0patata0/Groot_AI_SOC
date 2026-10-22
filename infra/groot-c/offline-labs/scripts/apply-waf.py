#!/usr/bin/env python3
"""Root-only installation of two reviewed files into the existing WAF.

The existing producer, scanner rules, image, mounts and container are unchanged.
The writable container layer survives restart/reboot. After an approved full
container recreation, reapply these files to the newly reviewed container ID
before enabling the TLS lab route. Never use this helper as an LLM/MCP tool.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

FILES = {
    'waf-log4shell-server.conf': '/etc/nginx/conf.d/zz-capstone-labs.conf',
    'REQUEST-900-CAPSTONE-LABS.conf': '/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-LABS.conf',
}
PRESERVED = (
    '/etc/nginx/conf.d/zz-capstone-evidence.conf',
    '/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf',
    '/etc/modsecurity.d/modsecurity.conf',
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container-id', required=True)
    parser.add_argument('--image-id', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'run as root on A')
    require(re.fullmatch(r'[0-9a-f]{64}', args.container_id), 'full reviewed container ID required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image_id), 'reviewed image ID required')
    docker = next((p for p in ('/usr/local/bin/docker', '/usr/bin/docker') if Path(p).is_file()), None)
    require(docker is not None, 'Docker is not installed')
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}

    def run(arguments, *, check=True):
        result = subprocess.run([docker, '--host', 'unix:///var/run/docker.sock', *arguments],
                                capture_output=True, timeout=60, env=env)
        if check and result.returncode:
            raise RuntimeError('Docker operation failed: ' + result.stderr.decode(errors='replace')[:3000])
        return result

    def inspect():
        row = json.loads(run(['inspect', 'waf']).stdout)[0]
        require(row['Id'] == args.container_id and row['Image'] == args.image_id and row['State']['Running'],
                'reviewed WAF identity/running state changed')
        return row

    def read(path):
        return run(['exec', '--user', '0', args.container_id, 'cat', path]).stdout

    original = inspect()
    preserved = {p: hashlib.sha256(read(p)).hexdigest() for p in PRESERVED}
    source = Path(__file__).resolve().parent.parent
    prepared = {}
    for name, destination in FILES.items():
        file = source / name
        stat = file.lstat()
        require(file.is_file() and not file.is_symlink() and stat.st_uid == 0 and not stat.st_mode & 0o022,
                'reviewed source must be root-owned and not group/world writable')
        raw = file.read_bytes()
        require(0 < len(raw) < 64 * 1024, 'unexpected configuration size')
        existing = run(['exec', '--user', '0', args.container_id, 'test', '-e', destination], check=False)
        if existing.returncode == 0:
            require(read(destination) == raw, 'different existing configuration needs explicit review: ' + destination)
        else:
            require(existing.returncode == 1, 'cannot inspect target configuration')
        prepared[name] = (file, destination, raw, existing.returncode == 1)

    created = []
    try:
        for file, destination, raw, absent in prepared.values():
            inspect()
            if absent:
                run(['cp', str(file), args.container_id + ':' + destination])
                created.append((destination, raw))
                run(['exec', '--user', '0', args.container_id, 'chmod', '0644', destination])
            require(read(destination) == raw, 'configuration readback mismatch')
        syntax = run(['exec', args.container_id, 'nginx', '-t']).stderr.decode(errors='replace')
        run(['exec', args.container_id, 'nginx', '-s', 'reload'])
    except Exception:
        for destination, raw in reversed(created):
            inspect()
            require(read(destination) == raw, 'rollback target changed; operator review required')
            run(['exec', '--user', '0', args.container_id, 'rm', '--', destination])
        run(['exec', args.container_id, 'nginx', '-t'])
        run(['exec', args.container_id, 'nginx', '-s', 'reload'])
        raise
    after = inspect()
    require(original['State']['StartedAt'] == after['State']['StartedAt'], 'container unexpectedly restarted')
    require(preserved == {p: hashlib.sha256(read(p)).hexdigest() for p in PRESERVED}, 'existing evidence/scanner configuration changed')
    print(json.dumps({'container_id': after['Id'], 'image_id': after['Image'], 'started_at': after['State']['StartedAt'],
                      'preserved_sha256': preserved, 'configuration_sha256': {name: hashlib.sha256(row[2]).hexdigest() for name, row in prepared.items()},
                      'syntax': syntax, 'reloaded_without_recreation': True,
                      'reapply_after_approved_full_recreation': True}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
