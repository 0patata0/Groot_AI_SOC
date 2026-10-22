"""Meaningful HTTP/auth contract tests; uses ASGI directly, no extra test packages."""
import asyncio
import importlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest
from http.cookies import SimpleCookie
from unittest.mock import patch


class AppTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.token = 't' * 43
        self.key = Path(self.temp.name) / 'token';self.key.write_text(self.token)
        self.env = patch.dict(os.environ, {'OFFLINE_LABS_MANIFEST': str(Path(__file__).with_name('cve_list.json')), 'OFFLINE_LABS_TOKEN_FILE': str(self.key),
                                          'OFFLINE_LABS_ORIGINS': 'https://log4shell.grootlab.duckdns.org,http://127.0.0.1:18090,http://localhost:18090'})
        self.env.start()
        self.module = importlib.import_module('app')
        self.app = self.module.create_app()
        self.life = self.app.router.lifespan_context(self.app)
        await self.life.__aenter__()

    async def asyncTearDown(self):
        await self.life.__aexit__(None, None, None)
        self.env.stop();self.temp.cleanup()

    async def request(self, path, method='GET', body=b'', token=False, extra=None, host=b'127.0.0.1:18090'):
        headers = [(b'host', host)]
        if token:headers.append((b'authorization', ('Bearer ' + self.token).encode()))
        if body:headers.append((b'content-type', b'application/json'))
        if extra:headers.extend(extra)
        scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':method,'scheme':'http','path':path,'raw_path':path.encode(),'query_string':b'','root_path':'','headers':headers,'client':('127.0.0.1',1234),'server':('127.0.0.1',18090)}
        sent = [];delivered = False
        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type':'http.request','body':body,'more_body':False}
            await asyncio.sleep(5)
            return {'type':'http.disconnect'}
        async def send(event):sent.append(event)
        await asyncio.wait_for(self.app(scope,receive,send),8)
        start=next(x for x in sent if x['type']=='http.response.start')
        self.response_headers = start['headers']
        content=b''.join(x.get('body',b'') for x in sent if x['type']=='http.response.body')
        return start['status'],content,dict(start['headers'])

    async def challenge_proof(self, extra=None, host=b'127.0.0.1:18090'):
        code, body, headers = await self.request('/api/challenge', extra=extra, host=host)
        self.assertEqual(code, 200)
        challenge = json.loads(body)
        self.assertEqual(set(challenge), {'challenge_id','message','expires_at','algorithm','key_derivation'})
        self.assertEqual(challenge['algorithm'], 'HMAC-SHA-256')
        self.assertEqual(challenge['key_derivation'], 'SHA-256')
        self.assertTrue(challenge['message'].isascii())
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertNotIn(self.token.encode(), body)
        self.assertNotIn(hashlib.sha256(self.token.encode()).hexdigest().encode(), body)
        proof = hmac.new(hashlib.sha256(self.token.encode()).digest(), challenge['message'].encode(), hashlib.sha256).hexdigest()
        return json.dumps({'challenge_id': challenge['challenge_id'], 'proof': proof}).encode()

    def response_cookies(self):
        cookies = SimpleCookie()
        for name, value in self.response_headers:
            if name == b'set-cookie':
                cookies.load(value.decode())
        return cookies

    async def test_only_primary_cookie_is_issued_or_deleted(self):
        from practice_mode import COOKIE, check
        public = b'log4shell.grootlab.duckdns.org'
        for host, extra in ((b'127.0.0.1:18090', []),
                            (public, [(b'x-forwarded-proto', b'https')])):
            payload = await self.challenge_proof(extra=extra, host=host)
            code, body, _ = await self.request('/api/session', 'POST', payload, extra=extra, host=host)
            self.assertEqual(code, 200)
            cookies = self.response_cookies()
            self.assertEqual(set(cookies), {COOKIE})
            self.assertEqual(cookies[COOKIE]['path'], '/')
            self.assertEqual(cookies[COOKIE]['samesite'], 'strict')
            self.assertTrue(cookies[COOKIE]['httponly'])
            self.assertEqual(bool(cookies[COOKIE]['secure']), host == public)
            self.assertEqual(check(self.token, cookies[COOKIE].value, '127.0.0.1'), json.loads(body)['expires_at'])
            for method, data, expected in (('DELETE', b'{}', 200), ('POST', b'{}', 401)):
                code, _, _ = await self.request('/api/session', method, data, host=host, extra=extra)
                self.assertEqual(code, expected)
                cookies = self.response_cookies()
                self.assertEqual(set(cookies), {COOKIE})
                self.assertEqual(cookies[COOKIE]['max-age'], '0')

    async def test_configured_https_origin_controls_secure_cookie(self):
        self.app.state.origins = {'https://training.example.test:8443', 'http://127.0.0.1:18090'}
        self.app.state.hosts = {'training.example.test:8443', '127.0.0.1:18090'}
        host = b'training.example.test:8443'
        payload = await self.challenge_proof(host=host)
        self.assertEqual((await self.request('/api/session', 'POST', payload, host=host))[0], 200)
        cookies = self.response_cookies()
        self.assertTrue(cookies['groot_lab_mode']['secure'])
        self.assertEqual((await self.request('/api/session', host=b'log4shell.grootlab.duckdns.org'))[0], 400)
        payload = await self.challenge_proof()
        self.assertEqual((await self.request('/api/session', 'POST', payload,
                                            extra=[(b'x-forwarded-proto', b'https')]))[0], 200)
        self.assertFalse(self.response_cookies()['groot_lab_mode']['secure'])

    async def test_unconfigured_application_allows_only_loopback_origins(self):
        with patch.dict(os.environ):
            os.environ.pop('OFFLINE_LABS_ORIGINS')
            app = self.module.create_app()
            async with app.router.lifespan_context(app):
                self.assertEqual(app.state.origins, {'http://127.0.0.1:18090', 'http://localhost:18090'})
                self.assertNotIn('log4shell.grootlab.duckdns.org', app.state.hosts)

    async def test_current_catalog_and_gateway_exclude_dvwa(self):
        expected = {'CVE-2021-44228', 'CVE-2021-41773', 'CVE-2021-42013', 'CVE-2021-3156'}
        code, body, _ = await self.request('/api/list')
        self.assertEqual(code, 200)
        self.assertEqual({row['cve_id'] for row in json.loads(body)}, expected)
        self.assertEqual(len(json.loads(body)), 4)
        self.assertEqual((await self.request('/api/gateway-session', extra=[
            (b'x-lab-gateway', b'1'), (b'x-lab-id', b'LAB-DVWA')]))[0], 404)

    async def test_retired_dvwa_cookie_cannot_authorize_current_routes(self):
        from practice_mode import COOKIE, issue
        retired_key = hmac.new(self.token.encode(), b'capstone-practice-dvwa-v1', hashlib.sha256).hexdigest()
        retired, _ = issue(retired_key, '127.0.0.1')
        public = b'log4shell.grootlab.duckdns.org'
        for cookie_name in ('__Secure-groot_lab_dvwa_mode', COOKIE):
            extra = [(b'x-forwarded-proto', b'https'), (b'cookie', (cookie_name + '=' + retired).encode())]
            code, body, _ = await self.request('/api/session', extra=extra, host=public)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)['mode'], 'enforce')
            for identifier in (b'CVE-2021-44228', b'CVE-2021-41773', b'CVE-2021-42013', b'CVE-2021-3156'):
                code, _, headers = await self.request('/api/gateway-session', host=public, extra=[
                    *extra, (b'x-lab-gateway', b'1'), (b'x-lab-id', identifier)])
                self.assertEqual(code, 204)
                self.assertEqual(headers[b'x-lab-mode'], b'enforce')
                self.assertEqual(headers[b'x-lab-cookie'], b'')
            self.assertEqual((await self.request('/api/gateway-session', host=public, extra=[
                *extra, (b'x-lab-gateway', b'1'), (b'x-lab-id', b'LAB-DVWA')]))[0], 404)

    async def test_primary_session_still_authorizes_java_with_origin_boundary(self):
        payload = await self.challenge_proof()
        code, _, headers = await self.request('/api/session', 'POST', payload)
        self.assertEqual(code, 200)
        cookie = headers[b'set-cookie'].split(b';', 1)[0]
        code, _, headers = await self.request('/api/gateway-session', extra=[
            (b'cookie', cookie), (b'x-lab-gateway', b'1'), (b'x-lab-id', b'CVE-2021-44228')])
        self.assertEqual(code, 204); self.assertEqual(headers[b'x-lab-mode'], b'exempt')
        self.assertEqual(headers[b'x-lab-cookie'], b'')
        with patch.object(self.module, 'rpc') as rpc:
            self.assertEqual((await self.request('/api/deploy', 'POST', b'{"cve_id":"CVE-2021-44228"}',
                                                extra=[(b'cookie', cookie), (b'origin', b'null')]))[0], 403)
            rpc.assert_not_called()

    async def test_anonymous_practice_and_enforced_default(self):
        self.assertEqual((await self.request('/api/list',token=False))[0],200)
        code,body,_=await self.request('/api/session',token=False)
        self.assertEqual(code,200);self.assertEqual(json.loads(body),{'mode':'enforce','expires_at':None})
        with patch.object(self.module,'rpc',return_value={'ok':True}) as mock:
            self.assertEqual((await self.request('/api/deploy','POST',b'{"cve_id":"CVE-2021-44228"}',token=False))[0],200)
            mock.assert_called_once_with('deploy','CVE-2021-44228')

    async def test_proof_is_only_for_short_lived_observation_session(self):
        self.assertEqual((await self.request('/api/session','POST',b'{}',token=False))[0],401)
        payload = await self.challenge_proof()
        code,body,headers=await self.request('/api/session','POST',payload)
        self.assertEqual(code,200);self.assertEqual(json.loads(body)['mode'],'exempt')
        self.assertNotIn(self.token.encode(),body+headers[b'set-cookie'])
        self.assertIn(b'HttpOnly',headers[b'set-cookie']);self.assertIn(b'SameSite=strict',headers[b'set-cookie'])
        cookie=headers[b'set-cookie'].split(b';',1)[0]
        code,body,_=await self.request('/api/session',token=False,extra=[(b'cookie',cookie)])
        self.assertEqual(json.loads(body)['mode'],'exempt')
        code,body,_=await self.request('/api/session',token=False,extra=[(b'cookie',cookie),(b'x-lab-client-ip',b'192.168.15.222')])
        self.assertEqual(json.loads(body)['mode'],'enforce')
        code,body,headers=await self.request('/api/session','DELETE',b'{}',token=False,extra=[(b'cookie',cookie)])
        self.assertEqual(json.loads(body)['mode'],'enforce');self.assertIn(b'Max-Age=0',headers[b'set-cookie'])

    async def test_invalid_proof_consumes_challenge_and_success_cannot_replay(self):
        payload = await self.challenge_proof()
        bad = json.loads(payload);bad['proof'] = '0' * 64
        self.assertEqual((await self.request('/api/session','POST',json.dumps(bad).encode()))[0],401)
        self.assertEqual((await self.request('/api/session','POST',payload))[0],401)
        payload = await self.challenge_proof()
        self.assertEqual((await self.request('/api/session','POST',payload))[0],200)
        self.assertEqual((await self.request('/api/session','POST',payload))[0],401)

    async def test_legacy_bearer_rejected_even_with_valid_proof(self):
        self.assertEqual((await self.request('/api/session','POST',b'{}',token=True))[0],401)
        payload = await self.challenge_proof()
        self.assertEqual((await self.request('/api/session','POST',payload,token=True))[0],401)
        self.assertEqual((await self.request('/api/session','POST',payload))[0],401)

    async def test_challenge_expiry_and_ip_binding(self):
        from challenge import ChallengeStore
        now = [1000]
        self.app.state.challenges = ChallengeStore(clock=lambda:now[0],monotonic=lambda:now[0])
        payload = await self.challenge_proof()
        now[0] = 1030
        self.assertEqual((await self.request('/api/session','POST',payload))[0],401)
        payload = await self.challenge_proof()
        self.assertEqual((await self.request('/api/session','POST',payload,extra=[(b'x-lab-client-ip',b'192.168.15.222')]))[0],401)
        self.assertEqual((await self.request('/api/session','POST',payload))[0],401)

    async def test_verification_errors_are_bounded_and_do_not_reflect_input(self):
        for body in (self.token.encode(), json.dumps([self.token]).encode(), json.dumps({'proof':self.token}).encode(), b'['*1200+b']'*1200):
            code,response,_ = await self.request('/api/session','POST',body)
            self.assertEqual(code,401);self.assertLess(len(response),512)
            self.assertNotIn(self.token.encode(),response)
        payload = json.loads(await self.challenge_proof());payload['unexpected'] = self.token
        self.assertEqual((await self.request('/api/session','POST',json.dumps(payload).encode()))[0],401)
        del payload['unexpected']
        self.assertEqual((await self.request('/api/session','POST',json.dumps(payload).encode()))[0],401)
        self.assertEqual((await self.request('/api/session','POST',b'x'*4097))[0],413)

    async def test_challenge_limits_and_cross_origin_denial(self):
        self.assertEqual((await self.request('/api/challenge',extra=[(b'origin',b'https://untrusted.invalid')]))[0],403)
        for _ in range(8):
            self.assertEqual((await self.request('/api/challenge'))[0],200)
        code,body,headers = await self.request('/api/challenge')
        self.assertEqual(code,429);self.assertLess(len(body),512)
        self.assertEqual(headers[b'retry-after'],b'30')

    async def test_existing_utf8_password_and_meaningful_spaces_are_supported(self):
        self.token = ' 현장실습예외암호🔑 '
        self.key.write_text(self.token+'\n',encoding='utf-8')
        replacement = self.module.create_app()
        original = self.app
        async with replacement.router.lifespan_context(replacement):
            self.assertEqual(replacement.state.token,self.token)
            try:
                self.app = replacement
                payload = await self.challenge_proof()
                code,body,headers = await self.request('/api/session','POST',payload)
                self.assertEqual(code,200)
                self.assertNotIn(self.token.encode(),body+headers[b'set-cookie'])
            finally:
                self.app = original

    async def test_password_file_length_bounds(self):
        for value in ('short7!', 'x'*257):
            self.key.write_text(value,encoding='utf-8')
            replacement = self.module.create_app()
            with self.assertRaisesRegex(RuntimeError,'invalid administrator token file'):
                async with replacement.router.lifespan_context(replacement):
                    self.fail('invalid password file accepted')

    async def test_gateway_only_returns_validated_mode_and_java_cookie(self):
        self.assertEqual((await self.request('/api/gateway-session',token=False))[0],404)
        code,_,headers=await self.request('/api/gateway-session',token=False,extra=[(b'x-lab-gateway',b'1'),(b'x-lab-id',b'CVE-2021-44228'),(b'x-capstone-lab-mode',b'exempt'),(b'cookie',b'groot_lab_mode=forged; groot_log4shell_java_http=abc.123; admin=secret')])
        self.assertEqual(code,204);self.assertEqual(headers[b'x-lab-mode'],b'enforce')
        self.assertEqual(headers[b'x-lab-cookie'],b'groot_log4shell_java_http=abc.123')

    async def test_gateway_requires_one_registered_proxy_selected_id(self):
        for ids in ([], [(b'x-lab-id',b'LAB-OTHER')], [(b'x-lab-id',b'CVE-2020-0000')],
                    [(b'x-lab-id',b'CVE-2021-44228'),(b'x-lab-id',b'CVE-2021-44228')]):
            self.assertEqual((await self.request('/api/gateway-session',extra=[(b'x-lab-gateway',b'1'),*ids]))[0],404)

    async def test_mixed_catalog_is_exact_and_gateway_filters_by_registered_lab(self):
        catalog = json.loads(Path(__file__).with_name('cve_list.json').read_text())
        catalog = [row for row in catalog if row['cve_id'] not in {'LAB-DVWA','CVE-2021-3156','CVE-2021-41773'}]
        java = next(row for row in catalog if row['cve_id']=='CVE-2021-44228')
        catalog.extend([
            {'type':'existing-http','cve_id':'LAB-DVWA','software':'DVWA','vulnerable_version':'training'},
            {'type':'local-cli','cve_id':'CVE-2021-3156','software':'sudo','vulnerable_version':'isolated'},
            {**java,'cve_id':'CVE-2021-41773','host_port':18999},
        ])
        path = Path(self.temp.name)/'mixed.json';path.write_text(json.dumps(catalog))
        with patch.dict(os.environ,{'OFFLINE_LABS_MANIFEST':str(path)}):
            replacement = self.module.create_app()
            async with replacement.router.lifespan_context(replacement):
                original,self.app=self.app,replacement
                try:
                    self.assertEqual(json.loads((await self.request('/api/list'))[1]),catalog)
                    raw=b'groot_lab_mode=forged; PHPSESSID=0123456789abcdef0123456789; security=low; groot_log4shell_java_http=abc.123'
                    for identifier,expected in ((b'LAB-DVWA',b'PHPSESSID=0123456789abcdef0123456789; security=low'),
                                                 (b'CVE-2021-41773',b''),(b'CVE-2021-3156',b'')):
                        code,_,headers=await self.request('/api/gateway-session',extra=[
                            (b'x-lab-gateway',b'1'),(b'x-lab-id',identifier),(b'cookie',raw)])
                        self.assertEqual(code,204);self.assertEqual(headers[b'x-lab-cookie'],expected)
                finally:
                    self.app=original

    async def test_selection_accepts_only_cve_or_exact_dvwa_identifier(self):
        with patch.object(self.module,'rpc',return_value={'ok':True}) as rpc:
            self.assertEqual((await self.request('/api/stop','POST',b'{"cve_id":"LAB-DVWA"}'))[0],200)
            rpc.assert_called_once_with('stop','LAB-DVWA')
            rpc.reset_mock()
            for identifier in ('LAB-OTHER','LAB-DVWA/../','LAB-DVWA\n'):
                self.assertEqual((await self.request('/api/stop','POST',json.dumps({'cve_id':identifier}).encode()))[0],422)
            rpc.assert_not_called()

    async def test_cross_origin_cannot_enable_observation(self):
        code,_,_=await self.request('/api/session','POST',b'{}',extra=[(b'origin',b'https://untrusted.invalid')])
        self.assertEqual(code,403)

    async def test_exact_manifest_and_local_assets(self):
        code,body,headers=await self.request('/api/list')
        self.assertEqual(code,200)
        self.assertEqual(json.loads(body),json.loads(Path(__file__).with_name('cve_list.json').read_text()))
        self.assertIn(b"script-src 'self'",headers[b'content-security-policy'])
        self.assertEqual((await self.request('/static/app.js',token=False))[0],200)
        self.assertEqual((await self.request('/docs'))[0],404)

    async def test_cross_origin_write_rejected(self):
        with patch.object(self.module,'rpc') as mock:
            code,_,_=await self.request('/api/deploy','POST',b'{"cve_id":"CVE-2021-44228"}',extra=[(b'origin',b'https://untrusted.invalid')])
            self.assertEqual(code,403);mock.assert_not_called()

    async def test_no_arbitrary_docker_parameters(self):
        with patch.object(self.module,'rpc') as mock:
            for payload in [{'cve_id':'CVE-2021-44228','image':'untrusted:latest'}, {'cve_id':';id'}, {'cve_id':5}]:
                self.assertEqual((await self.request('/api/deploy','POST',json.dumps(payload).encode()))[0],422)
            mock.assert_not_called()

    async def test_bound_body_and_valid_id(self):
        with patch.object(self.module,'rpc',return_value={'ok':True,'lab':{'status':'running'}}) as mock:
            self.assertEqual((await self.request('/api/deploy','POST',b'x'*4097))[0],413)
            mock.assert_not_called()
            self.assertEqual((await self.request('/api/deploy','POST',b'{"cve_id":"CVE-2021-44228"}'))[0],200)
            mock.assert_called_once_with('deploy','CVE-2021-44228')

    async def test_status_dictionary_adapted(self):
        with patch.object(self.module,'rpc',return_value={'ok':True,'labs':{'CVE-2021-44228':{'status':'not_deployed','image_present':True}}}):
            code,body,_=await self.request('/api/status')
            self.assertEqual(code,200);self.assertEqual(json.loads(body)['labs'][0]['cve_id'],'CVE-2021-44228')


if __name__=='__main__':unittest.main()
