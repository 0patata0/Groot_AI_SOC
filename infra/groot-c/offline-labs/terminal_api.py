"""Same-origin HTTP bridge to fixed, isolated container PTYs."""
import hashlib
import json
from pathlib import Path
import re
import socket
import stat
import struct

from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse
from practice_mode import client_address

LABS = {'CVE-2022-0543': 'redis', 'CVE-2017-7494': 'samba', 'CVE-2021-3156': 'sudo'}
SOCKET = '/run/capstone-nonweb-labs/control.sock'
ID = re.compile(r'[0-9a-f]{64}\Z')
MESSAGES = {
    'terminal_closed': '터미널 연결이 종료됐습니다. 다시 연결해 주세요.',
    'terminal_not_running': '실습환경을 먼저 시작해 주세요.',
    'terminal_limit': '열린 터미널이 많습니다. 사용하지 않는 터미널을 종료해 주세요.',
    'operation_in_progress': '환경을 준비하고 있습니다. 잠시 후 다시 연결해 주세요.',
    'terminal_unavailable': '터미널 서비스에 연결할 수 없습니다.',
    'invalid_input': '입력 크기나 형식을 확인해 주세요.',
}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def terminal_rpc(payload):
    try:
        path = Path(SOCKET)
        meta = path.lstat()
        if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) != 0o660:
            raise ValueError('untrusted socket')
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o750:
            raise ValueError('untrusted socket directory')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(100 if payload['action'] == 'terminal_open' else 60 if payload['action'] == 'terminal_close' else 15)
            conn.connect(SOCKET)
            _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                raise ValueError('untrusted peer')
            conn.sendall(json.dumps(payload, separators=(',', ':')).encode() + b'\n')
            frame = bytearray()
            while b'\n' not in frame:
                chunk = conn.recv(65537 - len(frame))
                if not chunk or len(frame) + len(chunk) > 65536:
                    raise ValueError('invalid response')
                frame.extend(chunk)
        if not frame.endswith(b'\n') or b'\n' in frame[:-1]:
            raise ValueError('invalid response')
        response = json.loads(frame, object_pairs_hook=unique)
        if not isinstance(response, dict) or type(response.get('ok')) is not bool:
            raise ValueError('invalid response')
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise HTTPException(503, detail={'code': 'terminal_unavailable', 'message': MESSAGES['terminal_unavailable']}) from None
    if not response['ok']:
        code = response.get('error')
        if code not in MESSAGES:
            code = 'terminal_unavailable'
        raise HTTPException(409, detail={'code': code, 'message': MESSAGES[code]})
    return response


def validate_body(action, body):
    if not isinstance(body, dict):
        raise ValueError()
    fields = {'open': {'cve_id', 'rows', 'cols'}, 'poll': {'session_id', 'cursor'},
              'input': {'session_id', 'data'}, 'resize': {'session_id', 'rows', 'cols'},
              'close': {'session_id'}}
    if action not in fields or set(body) != fields[action]:
        raise ValueError()
    if action == 'open':
        if body['cve_id'] not in LABS:
            raise ValueError()
    elif not isinstance(body['session_id'], str) or not ID.fullmatch(body['session_id']):
        raise ValueError()
    if action in ('open', 'resize'):
        if not (type(body['rows']) is int and type(body['cols']) is int
                and 2 <= body['rows'] <= 100 and 20 <= body['cols'] <= 300):
            raise ValueError()
    if action == 'poll' and (type(body['cursor']) is not int or not 0 <= body['cursor'] <= 2**63 - 1):
        raise ValueError()
    if action == 'input' and (not isinstance(body['data'], str) or not 0 < len(body['data']) <= 2732
                              or not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', body['data'])):
        raise ValueError()


def install_routes(app, boundary, base):
    @app.get('/terminal/{cve_id}/', dependencies=[Depends(boundary)])
    def terminal_page(cve_id: str, request: Request):
        if cve_id not in LABS or cve_id not in request.app.state.lab_ids or cve_id not in request.app.state.terminal_ids:
            raise HTTPException(404)
        return FileResponse(base / 'static' / 'terminal.html')

    @app.post('/api/terminal/{action}', dependencies=[Depends(boundary)])
    async def terminal(action: str, request: Request):
        # Browser capabilities stay in memory/JSON, never URLs or access logs.
        if request.query_params or request.headers.get('origin') not in request.app.state.origins:
            raise HTTPException(403, detail='같은 사이트에서 터미널을 열어 주세요.')
        try:
            body = json.loads(await request.body(), object_pairs_hook=unique)
            validate_body(action, body)
            payload = dict(body, action='terminal_' + action)
            if action == 'open':
                if body['cve_id'] not in request.app.state.lab_ids or body['cve_id'] not in request.app.state.terminal_ids:
                    raise ValueError()
                payload['lab'] = LABS[payload.pop('cve_id')]
            address = client_address(request)
            payload['owner'] = hashlib.sha256((request.headers['host'] + '\0' + address).encode()).hexdigest()
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise HTTPException(422, detail='터미널 요청 형식을 확인해 주세요.') from None
        # Avoid blocking the ASGI event loop for each ten-second poll.
        from starlette.concurrency import run_in_threadpool
        result = await run_in_threadpool(terminal_rpc, payload)
        return {key: value for key, value in result.items() if key != 'ok'}
