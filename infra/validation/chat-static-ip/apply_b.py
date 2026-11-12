#!/usr/bin/env python3
"""B (groot layout): pin the Mattermost chat network addresses. Run as root, once.

Usage: apply_b.py <candidate-compose-path>
Recreates mm-app and mm-postgres and the mattermost_mm-net network with the
same subnet/gateway and fixed addresses (mm-app 172.19.0.2 = the broker's
RULE_MM_SOURCE_CIDRS, mm-postgres 172.19.0.3). Data stays in bind mounts.
Chat is unavailable for the recreate (~1 min). On any failure after the
compose file is replaced, the backup is restored and `up -d` runs once more.
No retry beyond that; the result JSON says what happened.
"""
import hashlib
import json
import os
import subprocess
import sys
import time

D = '/home/groot_b/capstone/mattermost'
F = D + '/docker-compose.yml'
CURRENT_SHA = 'a9d599df8a4eace9eb14c0e04d6e8f1da441318bfe3b9e670f8fe2bd63bdba24'
CANDIDATE_SHA = '9fe147887eaea6a7d211492dca0f66614f3bafc999de7f9eb28d35f166ec3573'
ENV = '/etc/socbot/soc_bot.env'
WANT = {'mm-app': '172.19.0.2', 'mm-postgres': '172.19.0.3'}
COMPOSE = ['docker', 'compose', '-f', F, '--project-directory', D, '-p', 'mattermost']
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}


def sh(argv, timeout=60):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def sha(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def addresses():
    rc, o = sh(['docker', 'network', 'inspect', 'mattermost_mm-net', '--format',
                '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}'])
    return dict((k, v.split('/')[0]) for k, v in (x.split('=') for x in o.split())) if rc == 0 else {}


def healthy(limit=180):
    end = time.time() + limit
    while time.time() < end:
        rc, o = sh(['docker', 'inspect', 'mm-app', '--format', '{{.State.Health.Status}}'])
        rc2, p = sh(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5',
                     'http://10.200.10.10:8065/api/v4/system/ping'])
        if o == 'healthy' and p == '200':
            return True
        time.sleep(3)
    return False


def main():
    candidate = sys.argv[1]
    # Preconditions: exact reviewed files, current layout and broker setting.
    assert sha(F) == CURRENT_SHA, 'live_compose_changed'
    assert sha(candidate) == CANDIDATE_SHA, 'candidate_changed'
    assert addresses() == WANT, 'current_addresses_differ'
    env = open(ENV).read()
    assert env.count('RULE_MM_SOURCE_CIDRS=') == 1 and 'RULE_MM_SOURCE_CIDRS=172.19.0.2/32\n' in env, 'broker_source_differs'
    assert healthy(10), 'mattermost_not_healthy_before'
    st = os.stat(F)
    backup = F + '.bak-staticip-' + time.strftime('%Y%m%dT%H%M%S')
    with open(backup, 'xb') as b:
        b.write(open(F, 'rb').read())
    os.chown(backup, st.st_uid, st.st_gid); os.chmod(backup, st.st_mode & 0o7777)
    out['backup'] = backup
    data = open(candidate, 'rb').read()
    tmp = F + '.staticip.tmp'
    with open(tmp, 'xb') as t:
        t.write(data)
    os.chown(tmp, st.st_uid, st.st_gid); os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, F)
    out['compose_sha'] = sha(F)
    rc, o = sh(COMPOSE + ['up', '-d'], 300)
    out['up'] = [rc, o[-1200:]]
    ok = rc == 0 and healthy() and addresses() == WANT
    out['addresses'] = addresses()
    if not ok:
        with open(F + '.restore.tmp', 'xb') as r:
            r.write(open(backup, 'rb').read())
        os.chown(F + '.restore.tmp', st.st_uid, st.st_gid); os.chmod(F + '.restore.tmp', st.st_mode & 0o7777)
        os.replace(F + '.restore.tmp', F)
        rc2, o2 = sh(COMPOSE + ['up', '-d'], 300)
        out['restored'] = {'up': [rc2, o2[-800:]], 'healthy': healthy(), 'addresses': addresses(),
                           'compose_sha': sha(F)}
        out['status'] = 'failed_restored'
        return
    rc, o = sh(['docker', 'network', 'inspect', 'mattermost_mm-net', '--format', '{{json .IPAM.Config}}'])
    out['ipam'] = o
    out['broker_env_unchanged'] = 'RULE_MM_SOURCE_CIDRS=172.19.0.2/32\n' in open(ENV).read()
    out['status'] = 'applied'


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        out['status'] = 'refused_no_change'; out['reason'] = str(e)
    except Exception as e:  # report, never retry
        out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
