(() => {
  'use strict';

  const HISTORY_KEY = 'groot.log4shell.request-history.v1';
  const HISTORY_LIMIT = 20;
  const REQUEST_TIMEOUT_MS = 20000;
  const HEADER_VALUE = /^[A-Za-z0-9._ -]{1,64}$/;
  const MODES = new Set(['normal', 'missing-header']);
  const byId = (id) => document.getElementById(id);
  const ui = {
    connection: byId('connection-state'), refresh: byId('refresh-bootstrap'),
    name: byId('lab-name'), target: byId('lab-target'), form: byId('request-form'),
    input: byId('api-version'), fieldError: byId('field-error'),
    normal: byId('send-normal'), missing: byId('send-missing'),
    status: byId('status-message'), badge: byId('response-badge'),
    empty: byId('response-empty'), detail: byId('response-detail'),
    responsePanel: document.querySelector('.response-panel'),
    http: byId('response-status'), duration: byId('response-duration'),
    interpretation: byId('response-interpretation'), mode: byId('response-mode'),
    header: byId('response-header'), time: byId('response-time'),
    requestId: byId('response-id'), contentType: byId('response-content-type'),
    body: byId('response-body'), historyCount: byId('history-count'),
    clear: byId('clear-history'), historyEmpty: byId('history-empty'),
    table: byId('history-table-wrap'), rows: byId('history-rows'),
    storageNotice: byId('storage-notice'),
  };
  let csrf = '';
  let ready = false;
  let busy = false;
  let checking = false;
  let history = [];
  let storageUsable = true;

  const clock = new Intl.DateTimeFormat('ko-KR', {
    timeZone: 'Asia/Seoul', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  });

  function text(value, fallback = '—', limit = 65536) {
    return typeof value === 'string' && value.length ? value.slice(0, limit) : fallback;
  }

  function timeLabel(value) {
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? clock.format(date) : '시각 확인 불가';
  }

  function durationLabel(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? `${Math.round(value).toLocaleString('ko-KR')} ms` : '—';
  }

  function modeLabel(mode) {
    return mode === 'missing-header' ? '헤더 누락' : '정상 요청';
  }

  function httpTone(status) {
    if (status >= 200 && status < 400) return 'success';
    if (status >= 400 && status < 500) return 'warning';
    return 'error';
  }

  function badge(element, label, tone) {
    element.textContent = label;
    element.dataset.tone = tone;
  }

  function status(message, tone = 'neutral') {
    ui.status.textContent = message;
    ui.status.dataset.tone = tone;
  }

  function updateControls() {
    ui.normal.disabled = !ready || busy || checking;
    ui.missing.disabled = !ready || busy || checking;
    ui.input.disabled = busy || checking || !ready;
    ui.refresh.disabled = busy || checking;
    ui.clear.disabled = history.length === 0 && storageUsable;
    ui.responsePanel.setAttribute('aria-busy', String(busy));
  }

  function storageWarning(message) {
    ui.storageNotice.textContent = message;
    ui.storageNotice.hidden = false;
  }

  function safeHistoryEntry(row) {
    if (!row || typeof row !== 'object' || !MODES.has(row.mode)) return null;
    if (typeof row.at !== 'string' || !Number.isFinite(new Date(row.at).getTime())) return null;
    const http = Number.isInteger(row.http) && row.http >= 100 && row.http <= 599 ? row.http : null;
    return {
      at: row.at.slice(0, 64), mode: row.mode, http,
      duration: typeof row.duration === 'number' && Number.isFinite(row.duration) && row.duration >= 0 ? row.duration : null,
      id: typeof row.id === 'string' ? row.id.slice(0, 160) : '',
      outcome: row.outcome === 'response' && http !== null ? 'response' : 'error',
    };
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (raw === null) return;
      if (raw.length > 200000) throw new Error('history_limit');
      const saved = JSON.parse(raw);
      if (!Array.isArray(saved)) throw new Error('history_format');
      history = saved.slice(0, HISTORY_LIMIT).map(safeHistoryEntry).filter(Boolean);
    } catch (_) {
      storageUsable = false;
      storageWarning('저장된 이력을 읽을 수 없습니다. 이번 화면의 요청 요약만 임시로 표시합니다.');
    }
  }

  function saveHistory() {
    if (!storageUsable) return;
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (_) {
      storageUsable = false;
      storageWarning('브라우저 저장소를 사용할 수 없습니다. 이번 요청 이력은 화면을 닫으면 사라집니다.');
    }
  }

  function renderHistory() {
    ui.rows.replaceChildren();
    ui.historyCount.textContent = String(history.length);
    ui.historyEmpty.hidden = history.length > 0;
    ui.table.hidden = history.length === 0;
    for (const item of history) {
      const tr = document.createElement('tr');
      const labels = [timeLabel(item.at), modeLabel(item.mode),
        item.outcome === 'response' ? String(item.http) : '응답 확인 불가',
        durationLabel(item.duration), item.id || '—'];
      labels.forEach((label, index) => {
        const td = document.createElement('td');
        td.textContent = label;
        if (index === 2) {
          td.className = 'history-status';
          td.dataset.tone = item.outcome === 'response' ? httpTone(item.http) : 'error';
        }
        tr.appendChild(td);
      });
      ui.rows.appendChild(tr);
    }
    updateControls();
  }

  function addHistory(item) {
    const safe = safeHistoryEntry(item);
    if (!safe) return;
    history.unshift(safe);
    history = history.slice(0, HISTORY_LIMIT);
    saveHistory();
    renderHistory();
  }

  async function api(url, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(url, {
        credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        ...options, signal: controller.signal,
      });
      const content = await response.text();
      if (content.length > 262144) throw new Error('실습 API 응답이 화면에서 처리할 수 있는 크기를 초과했습니다. 서버의 응답 제한을 확인해 주세요.');
      let data;
      try { data = JSON.parse(content); } catch (_) {
        const error = new Error('API가 JSON 응답을 반환하지 않았습니다. 연결 상태와 Apache 구성을 확인해 주세요.');
        error.http = response.status;
        throw error;
      }
      if (!response.ok || !data || data.ok !== true) {
        const fallback = response.status === 429 ? '요청이 많습니다. 잠시 후 다시 시도해 주세요.'
          : response.status === 403 ? '요청 확인 정보가 만료되었거나 허용되지 않았습니다. 연결을 다시 확인해 주세요.'
            : '실습 서버 요청을 완료하지 못했습니다.';
        const error = new Error(text(data && data.error, fallback, 500));
        error.http = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('응답 대기 시간이 초과되었습니다. 요청이 서버에 도달했을 수 있으므로 결과를 확인한 뒤 다시 시도해 주세요.');
      if (error instanceof TypeError) throw new Error('서버에 연결할 수 없습니다. 네트워크와 실습 화면 주소를 확인해 주세요.');
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  async function bootstrap() {
    if (busy || checking) return;
    checking = true;
    ready = false;
    csrf = '';
    badge(ui.connection, '연결 확인 중', 'pending');
    status('실습 서버의 요청 설정을 확인하고 있습니다.');
    updateControls();
    try {
      const data = await api('api.php?action=bootstrap');
      if (typeof data.csrf !== 'string' || !data.csrf || data.csrf.length > 512 || !data.lab || typeof data.lab !== 'object') {
        throw new Error('연결 설정 형식이 올바르지 않습니다. 실습 API 구성을 확인해 주세요.');
      }
      csrf = data.csrf;
      ui.name.textContent = text(data.lab.name, 'Log4Shell 실습 서버', 160);
      ui.target.textContent = text(data.lab.target, '고정 실습 대상', 300);
      ready = true;
      badge(ui.connection, '요청 준비됨', 'success');
      status('요청 설정을 확인했습니다. 실습 서버의 실제 응답은 요청을 보낸 뒤 확인할 수 있습니다.');
    } catch (error) {
      badge(ui.connection, '연결 확인 실패', 'error');
      status(error.message, 'error');
    } finally {
      checking = false;
      updateControls();
    }
  }

  function showResponse(data, mode) {
    const req = data.request;
    const result = data.response;
    if (!req || !result || !Number.isInteger(result.status) || result.status < 100 || result.status > 599 || typeof result.body !== 'string') {
      throw new Error('실습 응답 형식이 올바르지 않습니다. API 응답 구조를 확인해 주세요.');
    }
    ui.empty.hidden = true;
    ui.detail.hidden = false;
    badge(ui.badge, `HTTP ${result.status}`, httpTone(result.status));
    ui.http.textContent = String(result.status);
    ui.duration.textContent = durationLabel(data.duration_ms);
    ui.interpretation.textContent = text(data.interpretation, '서버의 HTTP 응답을 수신했습니다. 상태 코드와 본문을 함께 확인해 주세요.', 2000);
    ui.mode.textContent = modeLabel(mode);
    ui.header.textContent = mode === 'missing-header' ? '전송하지 않음'
      : `${text(req.header_name, 'API 버전 헤더', 128)}: ${text(req.header_value, '(빈 값)', 64)}`;
    ui.time.textContent = `${timeLabel(req.started_at)} KST`;
    ui.requestId.textContent = text(req.id, '확인 불가', 160);
    ui.contentType.textContent = text(result.content_type, '없음', 200);
    ui.body.textContent = result.body.length ? result.body : '(응답 본문 없음)';
  }

  function showFailure(error, mode, at, duration) {
    ui.empty.hidden = true;
    ui.detail.hidden = false;
    badge(ui.badge, '응답 확인 불가', 'error');
    ui.http.textContent = '확인 불가';
    ui.duration.textContent = durationLabel(duration);
    ui.interpretation.textContent = error.message;
    ui.mode.textContent = modeLabel(mode);
    ui.header.textContent = '대상 서버 전달 여부 확인 불가';
    ui.time.textContent = `${timeLabel(at)} KST`;
    ui.requestId.textContent = '확인 불가';
    ui.contentType.textContent = '—';
    ui.body.textContent = error.http ? `실습 API HTTP ${error.http}\n대상 Log4Shell 서버의 HTTP 응답과 구분됩니다.`
      : '대상 서버 응답을 확인하지 못했습니다. 요청이 도달했는지는 서버 기록과 대조해 주세요.';
  }

  async function send(mode) {
    if (busy || checking || !ready || !MODES.has(mode)) return;
    const value = mode === 'missing-header' ? '' : ui.input.value;
    if (mode === 'normal' && !HEADER_VALUE.test(value)) {
      ui.input.setAttribute('aria-invalid', 'true');
      ui.fieldError.textContent = '허용된 문자로 1~64자를 입력해 주세요.';
      ui.fieldError.hidden = false;
      ui.input.focus();
      return;
    }
    ui.input.removeAttribute('aria-invalid');
    ui.fieldError.hidden = true;
    busy = true;
    const at = new Date().toISOString();
    const began = performance.now();
    badge(ui.badge, '응답 대기 중', 'pending');
    status(`${modeLabel(mode)}을 보내고 있습니다. 응답을 기다려 주세요.`);
    updateControls();
    try {
      const data = await api('api.php', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ mode, api_version: value }),
      });
      showResponse(data, mode);
      addHistory({ at: typeof data.request.started_at === 'string' ? data.request.started_at : at,
        mode, http: data.response.status, duration: data.duration_ms,
        id: data.request.id, outcome: 'response' });
      status(`대상 서버에서 HTTP ${data.response.status} 응답을 받았습니다. 아래 응답 내용을 확인해 주세요.`,
        data.response.status < 400 ? 'success' : 'neutral');
    } catch (error) {
      const elapsed = performance.now() - began;
      showFailure(error, mode, at, elapsed);
      addHistory({ at, mode, http: null, duration: elapsed, id: '', outcome: 'error' });
      status(error.message, 'error');
      if (error.http === 403) {
        ready = false;
        csrf = '';
        badge(ui.connection, '연결 재확인 필요', 'warning');
      }
    } finally {
      busy = false;
      updateControls();
    }
  }

  ui.form.addEventListener('submit', (event) => {
    event.preventDefault();
    send(event.submitter ? event.submitter.value : 'normal');
  });
  ui.input.addEventListener('input', () => {
    if (HEADER_VALUE.test(ui.input.value)) {
      ui.input.removeAttribute('aria-invalid');
      ui.fieldError.hidden = true;
    }
  });
  ui.refresh.addEventListener('click', bootstrap);
  ui.clear.addEventListener('click', () => {
    history = [];
    try {
      localStorage.removeItem(HISTORY_KEY);
      storageUsable = true;
      ui.storageNotice.hidden = true;
      status('이 브라우저의 요청 이력을 지웠습니다. 서버 기록은 유지됩니다.');
    } catch (_) {
      storageUsable = false;
      storageWarning('화면의 이력은 지웠지만 브라우저 저장소 삭제를 확인하지 못했습니다. 브라우저의 사이트 데이터 설정을 확인해 주세요.');
    }
    renderHistory();
  });

  loadHistory();
  renderHistory();
  bootstrap();
})();
