"""Offline administration UI. No Docker access, network downloads or shell commands."""
from contextlib import asynccontextmanager
from pathlib import Path
import json
import os
import socket
import time

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from challenge import ChallengeLimit, ChallengeStore
from manifest import load_manifest
from practice_mode import COOKIE, TTL, check, client_address, issue, safe_lab_cookies

BASE = Path(__file__).resolve().parent
MESSAGES = {
    'pinned_image_unavailable': '매니페스트에 고정된 이미지가 로컬에 없습니다. 관리자가 반입 상태를 확인해야 합니다.',
    'egress_guard_unverified': '실습망 격리 설정을 확인하지 못했습니다. 관리자 확인이 필요합니다.',
    'foreign_container_conflict': '같은 이름의 미관리 컨테이너가 있어 변경하지 않았습니다.',
    'image_missing': '준비된 로컬 이미지가 없습니다. 관리자가 이미지를 반입해야 합니다.',
    'image_id_mismatch': '이미지 태그와 승인된 이미지 ID가 다릅니다.',
    'container_conflict': '기존 컨테이너와 충돌하여 변경하지 않았습니다.',
    'operation_in_progress': '다른 작업이 진행 중입니다. 잠시 후 상태를 확인하세요.',
    'unknown_cve': '매니페스트에 등록되지 않은 실습 ID입니다.',
    'docker_failed': 'Docker 작업이 실패했습니다. 서버의 관리 로그를 확인하세요.',
    'broker_unavailable': '실행 서비스에 연결할 수 없습니다. 관리자 확인이 필요합니다.',
    'external_lab_managed_separately': '기존 서비스는 별도로 관리합니다. 이 화면에서는 실행하거나 중지하지 않습니다.',
    'local_cli_managed_separately': '로컬 CLI 실습은 별도 격리 환경에서 관리합니다. 웹에서 실행하거나 중지하지 않습니다.',
    'terminal_unavailable': '터미널 실습 서비스에 연결할 수 없습니다.',
    'invalid_terminal_response': '터미널 실습 상태를 확인하지 못했습니다.',
    'terminal_operation_failed': '터미널 실습 환경을 준비하지 못했습니다. 관리자 확인이 필요합니다.',
}


def rpc(action, cve_id=None):
    payload = {'action': action}
    if cve_id is not None:
        payload['cve_id'] = cve_id
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(240 if action == 'deploy' else 130)
            conn.connect(os.environ.get('OFFLINE_LABS_SOCKET', '/run/capstone-offline-labs/control.sock'))
            conn.sendall(json.dumps(payload).encode() + b'\n')
            data = bytearray()
            while b'\n' not in data:
                chunk = conn.recv(16384)
                if not chunk or len(data) + len(chunk) > 262144:
                    raise ValueError('invalid broker response')
                data.extend(chunk)
        result = json.loads(data.split(b'\n', 1)[0])
    except (OSError, ValueError):
        raise HTTPException(503, detail={'code': 'broker_unavailable', 'message': MESSAGES['broker_unavailable']}) from None
    if not result.get('ok'):
        code = result.get('error', 'operation_failed')
        raise HTTPException(409, detail={'code': code, 'message': MESSAGES.get(code, '실행 조건을 확인하지 못했습니다. 서버 상태를 점검하세요.')})
    return result


class Selection(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    cve_id: str = Field(pattern=r'^(?:CVE-[0-9]{4}-[0-9]{4,19}|LAB-DVWA)$', max_length=28)


class RequestBoundary:
    """Bound request bodies even without Content-Length; never log credentials."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = dict(scope['headers'])
        if len(headers.get(b'authorization', b'')) > 256 or len(headers.get(b'cookie', b'')) > 4096:
            return await JSONResponse({'detail': '요청이 너무 큽니다.'}, 413)(scope, receive, send)
        if scope['method'] in ('POST', 'PUT', 'PATCH', 'DELETE'):
            chunks, size = [], 0
            while True:
                event = await receive()
                if event['type'] == 'http.disconnect':
                    return
                size += len(event.get('body', b''))
                if size > 4096:
                    return await JSONResponse({'detail': '요청이 너무 큽니다.'}, 413)(scope, receive, send)
                chunks.append(event.get('body', b''))
                if not event.get('more_body', False):
                    break
            original_receive = receive
            delivered = False
            async def buffered():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {'type': 'http.request', 'body': b''.join(chunks), 'more_body': False}
                return await original_receive()
            receive = buffered
        await self.app(scope, receive, send)


def create_app():
    @asynccontextmanager
    async def lifespan(app):
        path = Path(os.environ.get('OFFLINE_LABS_MANIFEST', str(BASE / 'cve_list.json')))
        # Validate at startup and preserve the exact JSON values for /api/list.
        validated = load_manifest(path)
        app.state.catalog = json.loads(path.read_text())
        app.state.lab_ids = frozenset(item['cve_id'] for item in validated)
        app.state.terminal_ids = frozenset(item['cve_id'] for item in validated if item['type'] == 'managed-terminal')
        token_path = Path(os.environ.get('OFFLINE_LABS_TOKEN_FILE', '/etc/capstone-offline-labs/admin-token'))
        # A root-provisioned existing administrator password can be UTF-8.
        # Preserve meaningful whitespace; only a file's terminal LF is removed.
        token = token_path.read_text(encoding='utf-8').removesuffix('\n')
        if not 8 <= len(token) <= 256 or len(token.encode('utf-8')) > 1024:
            raise RuntimeError('invalid administrator token file')
        app.state.token = token
        app.state.challenges = ChallengeStore()
        app.state.origins = set(os.environ.get('OFFLINE_LABS_ORIGINS', 'http://127.0.0.1:18090,http://localhost:18090').split(','))
        app.state.hosts = {x.split('://', 1)[-1] for x in app.state.origins}
        yield
        app.state.challenges.clear()
        app.state.token = ''

    app = FastAPI(title='Groot Offline Labs', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(RequestBoundary)

    @app.middleware('http')
    async def security_headers(request, call_next):
        if request.headers.get('host', '') not in request.app.state.hosts:
            return JSONResponse({'detail': '허용되지 않은 호스트입니다.'}, 400)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        style = "'self' 'unsafe-inline'" if request.url.path.startswith('/terminal/') else "'self'"
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src " + style + "; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        return response

    def boundary(request: Request):
        origin = request.headers.get('origin')
        if origin and origin not in request.app.state.origins:
            raise HTTPException(403, detail={'code': 'origin_denied', 'message': '다른 출처의 요청은 허용되지 않습니다.'})
        if request.headers.get('sec-fetch-site') == 'cross-site':
            raise HTTPException(403, detail={'code': 'origin_denied', 'message': '다른 출처의 요청은 허용되지 않습니다.'})
        if request.method in ('POST', 'DELETE') and request.headers.get('content-type', '').split(';')[0] != 'application/json':
            raise HTTPException(415, detail='application/json 요청이 필요합니다.')

    def mode(request):
        expiry = check(request.app.state.token, request.cookies.get(COOKIE, ''), client_address(request))
        return {'mode': 'exempt' if expiry else 'enforce', 'expires_at': expiry}

    def secure_cookie(request):
        # Only root-configured HTTPS origins select Secure cookies. Do not
        # trust arbitrary forwarded headers or hardcode the deployment host.
        return 'https://' + request.headers.get('host', '') in request.app.state.origins

    @app.get('/healthz')
    def health():
        return {'status': 'ok', 'offline': True}

    @app.get('/api/session', dependencies=[Depends(boundary)])
    def session(request: Request):
        return mode(request)

    @app.get('/api/challenge', dependencies=[Depends(boundary)])
    def challenge(request: Request):
        try:
            return request.app.state.challenges.issue(client_address(request), request.headers.get('host', ''))
        except ChallengeLimit:
            raise HTTPException(429, detail={'code': 'challenge_limit', 'message': '잠시 후 WAF 실습 예외 키 검증을 다시 시도하세요.'}, headers={'Retry-After': '30'}) from None
        except ValueError:
            raise HTTPException(400, detail='접속 정보를 확인하지 못했습니다.') from None

    @app.post('/api/session', dependencies=[Depends(boundary)])
    async def enable_observation(request: Request):
        # Parse manually so validation errors never reflect submitted key/proof
        # material in a Pydantic error response. The middleware bounds the body.
        try:
            body = await request.json()
        except (ValueError, UnicodeError, RecursionError):
            body = None
        supplied = body if isinstance(body, dict) else {}
        address = client_address(request)
        verified = request.app.state.challenges.verify(
            request.app.state.token, supplied.get('challenge_id'), supplied.get('proof'),
            address, request.headers.get('host', ''))
        if not verified or set(supplied) != {'challenge_id', 'proof'} or 'authorization' in request.headers:
            response = JSONResponse({'detail': {'code': 'invalid_key', 'message': 'WAF 실습 예외 키 검증에 실패했습니다. 새 검증을 시작하세요.'}}, 401)
            response.delete_cookie(COOKIE, path='/', secure=secure_cookie(request), httponly=True, samesite='strict')
            return response
        issued_at = int(time.time())
        value, expiry = issue(request.app.state.token, address, now=issued_at)
        response = JSONResponse({'mode': 'exempt', 'expires_at': expiry})
        response.set_cookie(COOKIE, value, max_age=TTL, path='/', secure=secure_cookie(request), httponly=True, samesite='strict')
        return response

    @app.delete('/api/session', dependencies=[Depends(boundary)])
    def disable_observation(request: Request, body: dict):
        if body:
            raise HTTPException(422, detail='빈 JSON 객체가 필요합니다.')
        response = JSONResponse({'mode': 'enforce', 'expires_at': None})
        response.delete_cookie(COOKIE, path='/', secure=secure_cookie(request), httponly=True, samesite='strict')
        return response

    @app.get('/api/gateway-session', dependencies=[Depends(boundary)])
    def gateway_session(request: Request):
        # Public Nginx routes deny this exact URL. auth_request reaches it via
        # the A-only Apache backend; no key or mode cookie goes onward to WAF.
        if request.headers.get('x-lab-gateway') != '1':
            raise HTTPException(404)
        lab_ids = request.headers.getlist('x-lab-id')
        if len(lab_ids) != 1 or lab_ids[0] not in request.app.state.lab_ids:
            raise HTTPException(404)
        state = mode(request)
        return Response(status_code=204, headers={
            'X-Lab-Mode': state['mode'],
            'X-Lab-Cookie': safe_lab_cookies(request.headers.get('cookie', ''), lab_ids[0]),
        })

    @app.get('/api/list', dependencies=[Depends(boundary)])
    def catalog(request: Request):
        return request.app.state.catalog

    @app.get('/api/status', dependencies=[Depends(boundary)])
    def status():
        result = rpc('status')
        return {'labs': [{'cve_id': key, **value} for key, value in result['labs'].items()], 'checked_at': int(time.time()), 'offline': True, 'deployment_allowed': result.get('deployment_allowed', False), 'safety_error': result.get('safety_error')}

    @app.post('/api/deploy', dependencies=[Depends(boundary)])
    def deploy(body: Selection):
        return rpc('deploy', body.cve_id)

    @app.post('/api/stop', dependencies=[Depends(boundary)])
    def stop(body: Selection):
        return rpc('stop', body.cve_id)

    @app.get('/')
    def index():
        return FileResponse(BASE / 'static' / 'index.html')

    from terminal_api import install_routes
    install_routes(app, boundary, BASE)
    app.mount('/static', StaticFiles(directory=BASE / 'static'), name='static')
    return app


app = create_app()
