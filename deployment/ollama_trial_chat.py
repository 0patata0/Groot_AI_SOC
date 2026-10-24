#!/usr/bin/env python3
"""Operator-only provisioning of the optional Ollama Mattermost trial bot."""
import argparse
import json
import ipaddress
import os
from pathlib import Path
import pwd
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ollama_trial import ROOT, ETC, STATE, USER, safe, write, run, need, digest
from bot_profiles import asset as profile_asset, set_profile_image

UNIT = Path('/etc/systemd/system/capstone-ollama-chat.service')
CHAT_SOURCES = ('chat.py', 'chat_policy.py')
def local_base(value):
    p = urlsplit(value)
    need(p.scheme == 'http' and p.port == 8065 and not p.username and not p.password and
         not p.query and not p.fragment and not p.path, 'local_mattermost_url')
    need(ipaddress.ip_address(p.hostname).version == 4, 'mattermost_ipv4')
    addresses = json.loads(run(['ip', '-j', '-4', 'address']).stdout)
    local = {a['local'] for interface in addresses for a in interface.get('addr_info', [])}
    need(p.hostname in local, 'mattermost_must_be_on_this_host')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    def __init__(self, base):
        self.base = local_base(base) + '/api/v4'
        self.token = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, body=None, absent=False):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                     headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as response:
                need(response.status in (200, 201), 'mattermost_status')
                data = json.loads(response.read(4194305))
                return data, response.headers
        except urllib.error.HTTPError as exc:
            if absent and exc.code == 404:
                return None, {}
            raise ValueError('mattermost_http_' + str(exc.code)) from None


def service_text():
    return '''[Unit]
Description=Ollama read-only Mattermost trial bot
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=soc-ollama
Group=soc-ollama
WorkingDirectory=/var/lib/capstone-ollama-trial/chat
Environment=HOME=/var/lib/capstone-ollama-trial/chat TZ=Asia/Seoul PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ExecStart=/opt/capstone-ollama-trial/venv/bin/python -I -B /opt/capstone-ollama-trial/chat.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/capstone-ollama-trial/chat
MemoryMax=1G
TasksMax=128
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
'''


def verify():
    receipt = json.loads(safe(ETC / 'chat-receipt.json').read_text())
    for name, value in receipt['sources'].items():
        need(digest(safe(ROOT / name)) == value, 'chat_source_drift')
    need(digest(safe(UNIT)) == receipt['unit_sha256'], 'chat_unit_drift')
    p = run(['runuser', '-u', USER, '--', ROOT / 'venv/bin/python', '-I', '-B', ROOT / 'chat.py', '--check'], timeout=60)
    events = [json.loads(line) for line in p.stdout.decode().splitlines() if line.startswith('{')]
    need(any(e.get('event') == 'check_passed' and e['posts_sent'] == 0 for e in events), 'chat_probe')
    need(run(['systemctl', 'is-active', UNIT.name]).stdout.strip() == b'active', 'chat_service_inactive')
    need(run(['systemctl', 'is-enabled', UNIT.name]).stdout.strip() == b'enabled', 'chat_service_disabled')
    return {'status': 'verified', 'bot': 'ollama', 'channel': 'soc-ollama',
            'websocket': True, 'model_requests': 0, 'posts_sent': 0, 'service': UNIT.name,
            'channel_id': receipt['channel_id'], 'bot_id': receipt['bot_id']}


def install(source, admin, team_id, admin_id, hermes_channel_id, base_url):
    need(os.geteuid() == 0, 'operator_root_required')
    if (ETC / 'chat-receipt.json').exists():
        return verify()
    need((ETC / 'receipt.json').is_file(), 'trial_runtime_required')
    need(not (ETC / 'chat-pending.json').exists() and not (ETC / 'chat.json').exists() and not UNIT.exists(),
         'partial_chat_install_requires_review')
    need(all(re.fullmatch(r'[a-z0-9]{26}', x) for x in (team_id, admin_id, hermes_channel_id)), 'chat_ids')
    for name in CHAT_SOURCES:
        safe(source / 'infra/ollama-trial' / name)
    profile_asset('ollama', source / 'deployment/bot-icons')
    api = API(base_url)
    try:
        me, headers = api.call('POST', '/users/login', admin)
        api.token = headers.get('Token')
        need(api.token and me['id'] == admin_id and 'system_admin' in me['roles'].split(), 'admin_identity')
        team, _ = api.call('GET', '/teams/' + team_id)
        previous, _ = api.call('GET', '/channels/' + hermes_channel_id)
        need(previous['team_id'] == team_id and previous['name'] in ('soc-agent', 'soc', 'soc-hermes'), 'hermes_channel_identity')
        existing, _ = api.call('GET', '/users/username/ollama', absent=True)
        need(existing is None, 'ollama_username_already_exists')
        existing, _ = api.call('GET', '/teams/' + team_id + '/channels/name/soc-ollama', absent=True)
        need(existing is None, 'ollama_channel_already_exists')
        # Persist resource identities immediately; partial setup is reviewed, never guessed.
        pending = {'schema': 1, 'team_id': team_id, 'hermes_channel_before': previous}
        write(ETC / 'chat-pending.json', json.dumps(pending).encode(), mode=0o600)
        bot, _ = api.call('POST', '/bots', {'username': 'ollama', 'display_name': 'ollama',
            'description': 'DGX Ollama 기반 SOC 읽기 전용 시험 봇. soc-ollama 또는 DM에서 질문하세요.'})
        bid = bot['user_id']; pending['bot_id'] = bid
        write(ETC / 'chat-pending.json', json.dumps(pending).encode(), mode=0o600)
        pending['bot_profile'] = set_profile_image(base_url, api.token, bid, 'ollama',
                                                   source / 'deployment/bot-icons')
        write(ETC / 'chat-pending.json', json.dumps(pending).encode(), mode=0o600)
        api.call('POST', '/teams/' + team_id + '/members', {'team_id': team_id, 'user_id': bid})
        channel, _ = api.call('POST', '/channels', {'team_id': team_id, 'name': 'soc-ollama',
            'display_name': 'soc-ollama', 'type': 'P',
            'header': 'ollama 읽기 전용 시험 · 멘션 없이 질문 · 후속 질문은 같은 스레드 · 변경/승인은 기존 Hermes',
            'purpose': '기존 Hermes와 분리한 Ollama 기반 실행부 직접 비교'})
        cid = channel['id']; pending['channel_id'] = cid
        write(ETC / 'chat-pending.json', json.dumps(pending).encode(), mode=0o600)
        api.call('POST', '/channels/' + cid + '/members', {'user_id': bid})
        members, _ = api.call('GET', '/channels/' + cid + '/members')
        if admin_id not in {m['user_id'] for m in members}:
            api.call('POST', '/channels/' + cid + '/members', {'user_id': admin_id})
        token, _ = api.call('POST', '/users/' + bid + '/tokens', {'description': 'capstone-ollama-chat'})
        user = pwd.getpwnam(USER)
        config = {'schema': 1, 'base_url': base_url, 'username': 'ollama',
                  'bot_id': bid, 'channel_id': cid, 'team_id': team_id, 'allowed_users': [admin_id],
                  'token': token['token'], 'enabled_at_ms': int(time.time() * 1000)}
        write(ETC / 'chat.json', json.dumps(config).encode(), gid=user.pw_gid)
        pending['token_id'] = token['id']
        write(ETC / 'chat-pending.json', json.dumps(pending).encode(), mode=0o600)
        for name in CHAT_SOURCES:
            write(ROOT / name, (source / 'infra/ollama-trial' / name).read_bytes(), gid=user.pw_gid)
        state = STATE / 'chat'; state.mkdir(mode=0o700); os.chown(state, user.pw_uid, user.pw_gid)
        # Name update only: preserve channel ID, posts, members and routing IDs.
        if previous['name'] != 'soc-hermes' or previous['display_name'] != 'soc-hermes':
            api.call('PUT', '/channels/' + hermes_channel_id + '/patch',
                     {'name': 'soc-hermes', 'display_name': 'soc-hermes'})
        renamed, _ = api.call('GET', '/channels/' + hermes_channel_id)
        need(renamed['id'] == hermes_channel_id and renamed['name'] == 'soc-hermes', 'hermes_rename_verify')
        write(UNIT, service_text().encode(), mode=0o644)
        receipt = {'schema': 1, 'bot_id': bid, 'channel_id': cid, 'team_name': team['name'],
                   'bot_profile': pending['bot_profile'],
                   'token_id': token['id'], 'hermes_channel_id': hermes_channel_id,
                   'hermes_previous_name': previous['name'], 'new_listener': False,
                   'sources': {name: digest(ROOT / name) for name in CHAT_SOURCES},
                   'unit_sha256': digest(UNIT)}
        write(ETC / 'chat-receipt.json', json.dumps(receipt).encode(), mode=0o600)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', UNIT.name])
        return verify()
    finally:
        if api.token:
            try:
                api.call('POST', '/users/logout')
            except Exception:
                pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=('install', 'verify'))
    p.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--mattermost-url', default='http://127.0.0.1:8065')
    p.add_argument('--app-credentials', type=Path, default=Path('/opt/capstone/siem/app-credentials.json'))
    p.add_argument('--bootstrap-credentials', type=Path, default=Path('/opt/capstone-prereqs/siem.json'))
    args = p.parse_args()
    need(os.geteuid() == 0, 'operator_root_required')
    if args.action == 'verify' or (ETC / 'chat-receipt.json').exists():
        result = verify()
    else:
        app = json.loads(safe(args.app_credentials).read_text())
        initial = json.loads(safe(args.bootstrap_credentials).read_text())
        result = install(args.source_root,
                         {'login_id': initial['mattermost_admin_username'], 'password': initial['mattermost_admin_password']},
                         app['mattermost_team_id'], app['mattermost_admin_id'], app['mattermost_channel_id'], args.mattermost_url)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
