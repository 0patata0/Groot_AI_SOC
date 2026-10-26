#!/usr/bin/env python3
"""Root deploy.sh extension: shared chat with explicit requests and peer review."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import time
from urllib.parse import urlsplit

ROOT = Path('/opt/capstone-review-chat')
ETC = Path('/etc/capstone-review-chat')
STATE = Path('/var/lib/capstone-review-chat')
SOURCES = ('review_channel.py', 'review_channel_worker.py', 'review_channel_policy.py')
UNIT = '/etc/systemd/system/capstone-review-chat.service'


def unit_text():
    return '''[Unit]
Description=SOC shared chat routing and independent peer review
After=network-online.target docker.service capstone-ollama-chat.service
Wants=network-online.target
[Service]
Type=simple
# System-manager default UID 0; dispatcher rejects any other identity. An
# explicit User=root with the two restrictions below prevents this host's
# fixed child UID drop. Keep restrictions and drop the model to soc-ollama.
ExecStart=/usr/bin/python3 -I -B /opt/capstone-review-chat/review_channel.py
Environment=TZ=Asia/Seoul PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
KillMode=control-group
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
ReadWritePaths=/var/lib/capstone-review-chat
MemoryMax=2G
TasksMax=256
[Install]
WantedBy=multi-user.target
'''


def write(path, raw, mode=0o600):
    p = Path(path)
    if p.is_symlink():
        raise ValueError('destination_symlink')
    fd = os.open(p.with_name(p.name+'.new'), os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno()); os.fchmod(f.fileno(), mode)
    os.replace(p.with_name(p.name+'.new'), p)


def verify():
    receipt = json.loads((ETC/'receipt.json').read_bytes())
    for path, expected in receipt['files'].items():
        p = Path(path)
        if p.is_symlink() or p.stat().st_uid != 0 or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            raise ValueError('review_source_drift')
    subprocess.run(['systemctl','is-active','--quiet','capstone-review-chat.service'],check=True)
    for _ in range(20):
        if (STATE/'health.json').exists():
            health = json.loads((STATE/'health.json').read_bytes())
            pid = int(subprocess.check_output(['systemctl','show','capstone-review-chat.service','-p','MainPID','--value']))
            if health.get('last_poll') and health.get('pid') == pid and pid > 0:
                break
        time.sleep(.5)
    else:
        raise ValueError('review_poll_not_ready')
    if not 0 <= time.time()-health['last_poll'] <= 30:
        raise ValueError('review_poll_stale')
    return {'status':'verified','channel_id':receipt['channel_id'],'source_files':len(receipt['files']),
            'pending':health['pending'],'active':health['active'],'posts_sent':0}


def install(bundle, api, chat, bots, hermes_env, site_url):
    if os.geteuid() != 0 or set(bundle) != set(SOURCES) or set(bots) != {'hermes', 'ollama'}:
        raise ValueError('operator_and_exact_sources_required')
    if (ETC/'receipt.json').exists():
        return verify()
    if any(p.exists() for p in (ROOT, ETC, STATE, Path(UNIT))):
        raise ValueError('partial_review_install_requires_inspection')
    u = urlsplit(site_url)
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('review_site_url')
    for name, raw in bundle.items():
        compile(raw, name, 'exec')
    for engine, bid in bots.items():
        value,_ = api('GET','/users/'+bid)
        if not value.get('is_bot') or value.get('delete_at') or 'system_admin' in value.get('roles','').split():
            raise ValueError('review_bot_identity')
    channel,_ = api('GET','/teams/'+chat['team_id']+'/channels/name/soc-review-agent', absent=True)
    if channel is None:
        channel,_ = api('POST','/channels',{'team_id':chat['team_id'],'name':'soc-review-agent','display_name':'soc-review-agent',
            'type':'O','header':'@hermes / @ollama 직접 요청 · 둘 다 태그하고 서로 검증 요청 가능 · 멘션 없으면 역할 분담 · 스레드 없이 대화'})
    if channel['team_id'] != chat['team_id'] or channel.get('delete_at'):
        raise ValueError('review_channel_identity')
    for bid in bots.values():
        api('POST','/channels/'+channel['id']+'/members',{'user_id':bid})
    # Native listeners must exclude this channel before the dispatcher starts.
    env = Path(hermes_env).read_text()
    values = [line.split('=',1)[1] for line in env.splitlines() if line.startswith('CAPSTONE_MM_MANAGED_CHANNELS=')]
    if not values or channel['id'] not in shlex.split(values[0])[0].split(',') or channel['id'] not in chat.get('managed_channel_ids',[]):
        raise ValueError('native_listeners_must_exclude_review_channel')
    for p,mode in ((ROOT,0o755),(ETC,0o700),(STATE,0o700)):
        p.mkdir(mode=mode)
    files = {}
    for name,raw in bundle.items():
        p=ROOT/name;write(p,raw,0o644);files[str(p)]=hashlib.sha256(raw).hexdigest()
    config={'schema':1,'channel_id':channel['id'],'team_id':chat['team_id'],'allowed_users':chat['allowed_users'],
            'bots':bots,'hermes_env':str(hermes_env),'site_url':site_url.rstrip('/'),'enabled_at_ms':int(time.time()*1000)}
    write(ETC/'config.json',json.dumps(config).encode())
    write(UNIT,unit_text().encode(),0o644);files[UNIT]=hashlib.sha256(unit_text().encode()).hexdigest()
    write(ETC/'receipt.json',json.dumps({'schema':1,'channel_id':channel['id'],'files':files}).encode())
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now','capstone-review-chat.service'],check=True,capture_output=True)
    return {'status':'installed','channel_id':channel['id'],'files':files,'fresh_poll_verification_required':True}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('install','verify'))
    parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--mattermost-url',required=True)
    args=parser.parse_args()
    if args.action=='verify':
        print(json.dumps(verify()));return
    if (ETC/'receipt.json').exists():
        print(json.dumps(verify()));return
    # Fresh-server setup only. Live changes use this reviewed install function
    # after backing up/excluding the native listeners, never a fresh-host apply.
    from ollama_trial_chat import API
    app=json.loads(Path('/opt/capstone/siem/app-credentials.json').read_bytes())
    initial=json.loads(Path('/opt/capstone-prereqs/siem.json').read_bytes())
    chat_path=Path('/etc/capstone-ollama-trial/chat.json');chat=json.loads(chat_path.read_bytes())
    api=API(args.mattermost_url)
    try:
        me,headers=api.call('POST','/users/login',{'login_id':initial['mattermost_admin_username'],'password':initial['mattermost_admin_password']})
        api.token=headers.get('Token')
        if me['id']!=app['mattermost_admin_id'] or not api.token:raise ValueError('admin_identity')
        channel,_=api.call('GET','/teams/'+chat['team_id']+'/channels/name/soc-review-agent',absent=True)
        if channel is None:
            channel,_=api.call('POST','/channels',{'team_id':chat['team_id'],'name':'soc-review-agent','display_name':'soc-review-agent','type':'O'})
        chat['managed_channel_ids']=sorted(set(chat.get('managed_channel_ids',[])) | {channel['id']})
        meta=chat_path.stat();write(chat_path,json.dumps(chat).encode(),stat.S_IMODE(meta.st_mode));os.chown(chat_path,meta.st_uid,meta.st_gid)
        home=Path('/opt/capstone/siem/capstone-hermes');env=home/'.env';meta=env.stat()
        lines=env.read_text().splitlines();managed={channel['id']}
        for line in lines:
            if line.startswith('CAPSTONE_MM_MANAGED_CHANNELS='):
                managed.update(shlex.split(line.split('=',1)[1])[0].split(','))
        raw='\n'.join(line for line in lines if not line.startswith('CAPSTONE_MM_MANAGED_CHANNELS='))+'\nCAPSTONE_MM_MANAGED_CHANNELS='+','.join(sorted(managed))+'\n'
        write(env,raw.encode(),stat.S_IMODE(meta.st_mode));os.chown(env,meta.st_uid,meta.st_gid)
        subprocess.run(['docker','restart','capstone-hermes'],check=True,capture_output=True)
        subprocess.run(['systemctl','restart','capstone-ollama-chat.service'],check=True)
        cfg,_=api.call('GET','/config');site=cfg['ServiceSettings']['SiteURL'] or args.mattermost_url
        result=install({n:(args.source_root/'infra/hermes'/n).read_bytes() for n in SOURCES},api.call,chat,
                       {'hermes':app['mattermost_bot_id'],'ollama':chat['bot_id']},env,site)
        print(json.dumps(result))
    finally:
        if api.token:api.call('POST','/users/logout')


if __name__=='__main__':
    main()
