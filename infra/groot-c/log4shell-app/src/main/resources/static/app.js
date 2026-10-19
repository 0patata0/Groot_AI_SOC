'use strict';
(() => {
  const byId = id => document.getElementById(id);
  const form = byId('request-form');
  const submit = byId('submit');
  let csrfToken = '';
  let busy = false;
  const timeFormat = new Intl.DateTimeFormat('ko-KR', { timeZone: 'Asia/Seoul', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  const source = () => form.elements.source.value;
  function notice(message, error = false) { byId('notice').textContent = message; byId('notice').className = error ? 'notice error' : 'notice'; }
  function connection(message, state) { byId('connection').textContent = message; byId('status-dot').className = `status-dot ${state || ''}`; }
  function badge(message, state) { byId('result-badge').textContent = message; byId('result-badge').className = `result-badge ${state || ''}`; }
  async function readJson(response) {
    const text = await response.text();
    try { return JSON.parse(text); } catch (_) { throw new Error(`서버가 JSON 응답을 반환하지 않았습니다. HTTP ${response.status}`); }
  }
  async function bootstrap() {
    csrfToken = ''; submit.disabled = true; byId('refresh').disabled = true;
    connection('서버 연결 중', '');
    try {
      const response = await fetch('api/status', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
      const data = await readJson(response);
      if (!response.ok || !data.ok || typeof data.csrfToken !== 'string') throw new Error('실습 API 연결을 확인하지 못했습니다.');
      csrfToken = data.csrfToken;
      byId('core-version').textContent = data.log4jCoreVersion || '확인 불가';
      byId('java-version').textContent = data.javaVersion || '확인 불가';
      connection('API 연결됨', 'ready');
      submit.disabled = busy;
      return true;
    } catch (error) { connection('연결 확인 필요', 'error'); notice(error.message, true); return false; }
    finally { byId('refresh').disabled = false; }
  }
  function updateInputHelp() {
    const isHeader = source() === 'header';
    byId('input-kind').textContent = isHeader ? 'X-Api-Version 헤더' : 'message 파라미터';
    byId('input-help').textContent = isHeader
      ? '서버는 수신한 헤더 값을 그대로 기록합니다. 브라우저는 헤더 앞뒤 공백을 정리하며, 줄바꿈·한글 등 일부 문자는 헤더로 보낼 수 없습니다.'
      : '서버가 받은 message 값을 변경 없이 logger.info()에 전달합니다. 한글과 줄바꿈도 파라미터로 보낼 수 있습니다.';
  }
  form.addEventListener('change', updateInputHelp);
  updateInputHelp();
  byId('refresh').addEventListener('click', () => { if (!busy) { notice(''); bootstrap(); } });
  byId('reset').addEventListener('click', () => { if (!busy) { byId('input-value').value = 'Groot logging lab'; byId('input-value').focus(); } });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !csrfToken) return;
    busy = true; submit.disabled = true; byId('refresh').disabled = true;
    byId('reset').disabled = true; badge('전송 중', ''); notice('');
    const selected = source();
    const value = byId('input-value').value;
    const body = new URLSearchParams({ source: selected });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8', Accept: 'application/json', 'X-Lab-CSRF-Token': csrfToken };
    if (selected === 'header') { body.set('headerName', 'X-Api-Version'); headers['X-Api-Version'] = value; }
    else { body.set('message', value); }
    const started = performance.now();
    try {
      const response = await fetch('api/log', { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers, body });
      const elapsed = performance.now() - started;
      const data = await readJson(response);
      byId('empty-state').hidden = true; byId('result').hidden = false;
      byId('http-status').textContent = String(response.status);
      byId('elapsed').textContent = `${Math.round(elapsed)} ms`;
      byId('result-source').textContent = selected === 'header' ? 'X-Api-Version' : 'message';
      byId('result-time').textContent = data.time ? `${timeFormat.format(new Date(data.time))} KST` : '—';
      byId('logged-message').textContent = data.ok && typeof data.message === 'string' ? data.message : '로깅 완료를 확인하지 못했습니다.';
      byId('request-id').textContent = data.requestId || '—';
      byId('level').textContent = data.ok ? data.level || 'INFO' : '—';
      if (!response.ok || !data.ok) {
        badge('실패', 'error');
        if (data.error === 'csrf_refresh_required') {
          const refreshed = await bootstrap();
          notice(refreshed ? '실습 세션을 갱신했습니다. 요청을 다시 보내 주세요. 기존 요청을 자동 재전송하지 않았습니다.' : '실습 세션을 갱신하지 못했습니다. 서버 연결을 다시 확인해 주세요. 요청은 자동 재전송하지 않았습니다.', true);
        }
        else { notice(`요청을 처리하지 못했습니다. ${data.error || `HTTP ${response.status}`}`, true); }
        return;
      }
      badge('기록됨', 'success'); notice('Java 로깅 호출을 마쳤습니다. 실제 로그와 패킷·탐지 결과는 실습 도구에서 대조하세요.');
    } catch (error) { badge('응답 확인 실패', 'error'); notice(`${error.message} 응답 유실 시 서버에 기록됐을 수도 있습니다.`, true); }
    finally { busy = false; submit.disabled = !csrfToken; byId('refresh').disabled = false; byId('reset').disabled = false; }
  });
  bootstrap();
})();
