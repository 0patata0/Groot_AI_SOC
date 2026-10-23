"use strict";

(function () {
  const LABS = {"CVE-2022-0543": "Redis", "CVE-2017-7494": "Samba", "CVE-2021-3156": "sudo"};
  const SESSION = /^[0-9a-f]{64}$/;
  const INPUT_CHUNK = 2048;
  const INPUT_LIMIT = 16384;
  const PASTE_LIMIT = 8192;
  const RESPONSE_LIMIT = 393216;

  function dimensions(cols, rows) {
    return {cols: Math.max(20, Math.min(300, Math.floor(cols) || 80)),
      rows: Math.max(2, Math.min(100, Math.floor(rows) || 24))};
  }
  function base64(bytes) {
    let raw = "";
    for (const byte of bytes) raw += String.fromCharCode(byte);
    return btoa(raw);
  }
  function outputBytes(value) {
    if (typeof value !== "string" || value.length > 262144 || value.length % 4 !== 0 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw new Error("invalid_output");
    }
    return Uint8Array.from(atob(value), char => char.charCodeAt(0));
  }
  function pollResult(value, cursor) {
    if (!value || !Number.isSafeInteger(value.cursor) || value.cursor < cursor ||
        typeof value.truncated !== "boolean" || typeof value.closed !== "boolean") throw new Error("invalid_poll");
    return {bytes: outputBytes(value.data), cursor: value.cursor, truncated: value.truncated, closed: value.closed};
  }

  // Every input request is ordered, bounded and sent once. An uncertain write
  // stops the queue instead of silently replaying a command.
  class InputQueue {
    constructor(send, failure) {
      this.send = send; this.failure = failure;
      this.queue = []; this.size = 0; this.active = true; this.sending = false;
    }
    push(bytes) {
      if (!this.active || bytes.length > INPUT_LIMIT || this.size + bytes.length > INPUT_LIMIT) return false;
      for (let start = 0; start < bytes.length; start += INPUT_CHUNK) this.queue.push(bytes.slice(start, start + INPUT_CHUNK));
      this.size += bytes.length;
      this.flush();
      return true;
    }
    async flush() {
      if (this.sending || !this.active) return;
      this.sending = true;
      try {
        while (this.active && this.queue.length) {
          const bytes = this.queue.shift();
          try { await this.send(base64(bytes)); }
          finally { this.size -= bytes.length; bytes.fill(0); }
        }
      } catch (_) {
        if (this.active) { this.stop(); this.failure(); }
      } finally { this.sending = false; }
    }
    stop() {
      this.active = false;
      for (const bytes of this.queue) { this.size -= bytes.length; bytes.fill(0); }
      this.queue = [];
    }
  }

  async function readJson(response) {
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > RESPONSE_LIMIT) throw new Error("response_too_large");
    if (!response.body || typeof response.body.getReader !== "function") throw new Error("stream_reader_unavailable");
    const reader = response.body.getReader();
    const pieces = [];
    let size = 0;
    try {
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > RESPONSE_LIMIT) throw new Error("response_too_large");
        pieces.push(value);
      }
    } finally {
      if (size > RESPONSE_LIMIT) await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const value of pieces) { bytes.set(value, offset); offset += value.length; }
    return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
  }

  if (typeof module === "object" && module.exports) {
    module.exports = {dimensions, base64, outputBytes, pollResult, InputQueue, readJson};
    return;
  }

  const $ = id => document.getElementById(id);
  const match = window.location.pathname.match(/^\/log4shell\/terminal\/(CVE-[0-9]{4}-[0-9]+)\/?$/);
  const cve = match && Object.hasOwn(LABS, match[1]) ? match[1] : null;
  const sudoLab = cve === "CVE-2021-3156";
  const screen = $("terminal-screen");
  const encoder = new TextEncoder();
  let terminal, fit, session = null, epoch = 0, cursor = 0, busy = false, gone = false;
  let input = null, resizeTimer = null, resizing = false, pendingSize = null;
  const requests = new Set();
  const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

  function status(message, kind = "") {
    $("terminal-status").textContent = message;
    $("terminal-status").dataset.state = kind;
  }
  function notice(message) { $("terminal-notice").textContent = message; }
  function controls() {
    $("terminal-reconnect").disabled = !cve || busy || gone || !terminal || (sudoLab && !!session);
    $("terminal-close").disabled = !session || busy || gone;
    if (terminal) terminal.options.disableStdin = !session || busy || gone;
  }
  async function request(action, body, timeout = 15000) {
    const controller = new AbortController();
    requests.add(controller);
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch("/log4shell/api/terminal/" + action, {
        method: "POST", credentials: "same-origin", mode: "same-origin", cache: "no-store", redirect: "error",
        // no-referrer + non-CORS POST serializes Origin as null. Keep the
        // same-origin request restriction and send only the origin as referrer.
        referrerPolicy: "strict-origin",
        headers: {"Content-Type": "application/json", Accept: "application/json"},
        body: JSON.stringify(body), signal: controller.signal
      });
      if (!response.ok) throw new Error("terminal_request_failed");
      return await readJson(response);
    } finally { clearTimeout(timer); requests.delete(controller); }
  }
  function stopPending() {
    epoch += 1;
    if (input) input.stop();
    input = null;
    for (const controller of requests) controller.abort();
    requests.clear();
    clearTimeout(resizeTimer);
    pendingSize = null;
  }
  async function disconnect(message = "연결 종료됨", kind = "") {
    if (busy) return;
    busy = true;
    const previous = session;
    session = null;
    stopPending(); controls();
    status("연결 종료 중");
    let closed = true;
    if (previous) {
      try { await request("close", {session_id: previous}, sudoLab ? 30000 : 8000); }
      catch (_) { closed = false; }
    }
    busy = false;
    status(message, kind); controls();
    if (sudoLab && !previous) {
      notice("활성 sudo 터미널 연결이 없습니다. 콘솔에서 실습 환경 상태를 확인하세요.");
      return;
    }
    notice(closed
      ? (sudoLab ? "터미널 연결과 sudo 실습 환경이 종료됐습니다. 다시 사용하려면 콘솔에서 환경을 시작하세요."
        : "터미널 연결이 끝났습니다. 실습 환경은 콘솔에서 중지할 수 있습니다.")
      : (sudoLab ? "종료 결과를 확인하지 못했습니다. 서버의 제한 시간에 따라 sudo 환경도 중지됩니다. 콘솔에서 상태를 확인하세요."
        : "연결 종료 결과를 확인하지 못했습니다. 남은 연결은 서버의 제한 시간에 만료됩니다."));
  }
  async function poll(id, generation) {
    let failures = 0;
    while (!gone && session === id && epoch === generation) {
      try {
        const result = pollResult(await request("poll", {session_id: id, cursor}), cursor);
        if (gone || session !== id || epoch !== generation) return;
        if (result.truncated) notice("출력이 많아 이전 일부가 생략되었습니다.");
        if (result.bytes.length) await new Promise(resolve => terminal.write(result.bytes, resolve));
        if (gone || session !== id || epoch !== generation) return;
        cursor = result.cursor;
        if (failures) status("연결됨");
        failures = 0;
        if (result.closed) { await disconnect("연결 종료됨"); return; }
        // Even an immediately-empty server response cannot create a busy loop.
        await delay(result.bytes.length ? 50 : 250);
      } catch (_) {
        if (gone || session !== id || epoch !== generation) return;
        failures += 1;
        if (failures >= 3) { await disconnect("연결을 확인할 수 없습니다", "error"); return; }
        status("연결 확인 중");
        await delay(500 * (2 ** (failures - 1)));
      }
    }
  }
  function measure() {
    const proposed = fit.proposeDimensions();
    const size = dimensions(proposed?.cols || 80, proposed?.rows || 24);
    terminal.resize(size.cols, size.rows);
    $("terminal-size").textContent = size.cols + " × " + size.rows;
    return size;
  }
  async function sendResize() {
    if (resizing || !session || busy || gone) return;
    resizing = true;
    const generation = epoch;
    const id = session;
    try {
      while (pendingSize && session === id && epoch === generation && !gone) {
        const size = pendingSize;
        pendingSize = null;
        await request("resize", {session_id: id, ...size}, 8000);
      }
    } catch (_) {
      if (session === id && epoch === generation && !gone) await disconnect("연결을 확인할 수 없습니다", "error");
    } finally { resizing = false; }
  }
  function resized() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { pendingSize = measure(); sendResize(); }, 150);
  }
  async function connect() {
    if (busy || gone || !cve || !terminal) return;
    if (sudoLab && session) return;
    if (session) await disconnect();
    if (gone) return;
    busy = true;
    stopPending(); controls();
    const generation = epoch;
    status("연결 중");
    notice("실행 중인 실습 환경에 연결하고 있습니다.");
    terminal.reset();
    try {
      const opened = await request("open", {cve_id: cve, ...measure()}, 110000);
      if (generation !== epoch || gone) return;
      if (!opened || typeof opened.session_id !== "string" || !SESSION.test(opened.session_id) ||
          !Number.isSafeInteger(opened.expires_in) || opened.expires_in < 1 || opened.expires_in > 86400) {
        throw new Error("invalid_session");
      }
      session = opened.session_id;
      cursor = 0;
      const id = session;
      input = new InputQueue(data => {
        if (session !== id || epoch !== generation || gone) throw new Error("session_closed");
        return request("input", {session_id: id, data}, 10000);
      }, () => { if (session === id && epoch === generation && !gone) disconnect("입력 전송을 확인할 수 없습니다", "error"); });
      busy = false;
      status("연결됨"); controls();
      notice(sudoLab
        ? "sudo 터미널은 한 번에 하나만 연결합니다. 연결 종료·입력 유휴 5분·전체 30분 만료·터미널 서비스 종료 시 실습 환경도 중지됩니다."
        : "현재 실습 터미널에 연결되었습니다. 연결 종료는 환경을 중지하지 않습니다.");
      terminal.focus();
      poll(id, generation);
    } catch (_) {
      if (generation === epoch && !gone) {
        session = null;
        status("연결할 수 없습니다", "error");
        notice(sudoLab
          ? "콘솔에서 sudo 환경과 사용 중인 터미널을 확인하세요. 종료된 환경은 다시 시작한 뒤 연결해야 합니다."
          : "콘솔에서 실습 환경이 실행 중인지 확인한 뒤 재연결하세요.");
      }
    } finally { if (generation === epoch) { busy = false; controls(); } }
  }
  function queue(bytes) {
    if (!session || busy || !input || gone) return;
    if (!input.push(bytes)) notice("한 번에 보낼 수 있는 입력량을 넘었습니다. 짧게 나누어 입력하세요.");
  }
  function applyTheme() {
    if (!terminal) return;
    const light = document.documentElement.getAttribute("data-groot-theme") === "light";
    terminal.options.theme = light ? {
      background: "#f5f3ee", foreground: "#292923", cursor: "#45463e", cursorAccent: "#f5f3ee",
      selectionBackground: "#c5c1b680", black: "#292923", brightBlack: "#68675f", white: "#eae7df", brightWhite: "#fffefa"
    } : {background: "#181817", foreground: "#eeede7", cursor: "#d5d2c5", cursorAccent: "#181817",
      selectionBackground: "#b4b2a94d", black: "#181817", brightBlack: "#68675f", white: "#d5d2c5", brightWhite: "#eeede7"};
  }

  if (!cve || typeof window.Terminal !== "function" || typeof window.FitAddon?.FitAddon !== "function") {
    status("터미널을 준비할 수 없습니다", "error");
    notice("콘솔에서 지원되는 실습을 선택해 다시 열어주세요.");
    return;
  }
  document.title = LABS[cve] + " 터미널 · Lab Console";
  $("terminal-title").textContent = LABS[cve] + " 터미널";
  $("terminal-cve").textContent = cve;
  terminal = new window.Terminal({cols: 80, rows: 24, scrollback: 1000, fontSize: 14, lineHeight: 1.2,
    fontFamily: 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace',
    cursorBlink: false, convertEol: false, disableStdin: true, allowProposedApi: false,
    rightClickSelectsWord: false, screenReaderMode: true});
  fit = new window.FitAddon.FitAddon();
  terminal.loadAddon(fit);
  terminal.parser.registerOscHandler(52, () => true); // Never grant remote clipboard access.
  terminal.parser.registerOscHandler(8, () => true); // No output-generated hyperlinks.
  terminal.open(screen);
  terminal.onData(data => queue(encoder.encode(data)));
  terminal.onBinary(data => queue(Uint8Array.from(data, char => char.charCodeAt(0) & 255)));
  screen.addEventListener("paste", event => {
    const data = event.clipboardData?.getData("text/plain");
    if (typeof data !== "string" || data.length > PASTE_LIMIT || encoder.encode(data).length > PASTE_LIMIT) {
      event.preventDefault(); event.stopImmediatePropagation();
      notice("붙여넣기는 UTF-8 기준 8 KiB 이하로 나누어 주세요.");
    }
  }, true);
  $("terminal-reconnect").addEventListener("click", connect);
  $("terminal-close").addEventListener("click", () => disconnect());
  new MutationObserver(applyTheme).observe(document.documentElement, {attributes: true, attributeFilter: ["data-groot-theme"]});
  if (typeof ResizeObserver === "function") new ResizeObserver(resized).observe(screen);
  window.addEventListener("resize", resized);
  window.addEventListener("pagehide", () => {
    gone = true;
    const id = session;
    session = null;
    stopPending(); controls();
    if (id) fetch("/log4shell/api/terminal/close", {method: "POST", credentials: "same-origin", mode: "same-origin",
      cache: "no-store", redirect: "error", referrerPolicy: "strict-origin", keepalive: true,
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({session_id: id})}).catch(() => {});
  });
  window.addEventListener("pageshow", event => {
    if (event.persisted) { gone = false; busy = false; status("연결 종료됨"); controls(); }
  });
  applyTheme();
  if (document.fonts?.ready) document.fonts.ready.then(resized);
  connect();
}());
