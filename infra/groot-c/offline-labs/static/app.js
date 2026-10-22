"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const secureOrigin = window.location.protocol === "https:" || window.location.protocol === "http:" &&
    (window.location.hostname === "localhost" || /^127(?:\.\d{1,3}){3}$/.test(window.location.hostname));
  const subtle = window.crypto?.subtle;
  const signingAvailable = secureOrigin && window.isSecureContext === true && typeof TextEncoder === "function" &&
    !!subtle && ["digest", "importKey", "sign"].every((method) => typeof subtle[method] === "function");
  const state = {
    busy: false, sessionBusy: false, action: "", epoch: 0, closed: false,
    labs: [], catalogLoaded: false, statuses: new Map(), selected: "CVE-2021-44228",
    statusFresh: false, lastUpdated: null, refreshing: false, deploymentAllowed: false, safetyError: false,
    mode: "enforce", expiresAt: null, sessionFresh: false, expiryChecked: false,
    poll: null, clock: null, controllers: new Set(), policy: "", url: ""
  };
  const runnableStates = new Set(["stopped", "exited", "created", "absent", "not_created", "not_deployed", "missing"]);
  const statusLabels = {
    running: "실행 중", stopped: "중지됨", exited: "중지됨", created: "실행 전",
    absent: "실행 전", not_created: "실행 전", not_deployed: "실행 전", missing: "실행 전",
    restarting: "재시작 중", paused: "일시 중지", dead: "오류", error: "오류",
    conflict: "설정 충돌", unknown: "상태 미확인", external: "기존 서비스 연결",
    needs_setup: "별도 환경 준비 필요", ready: "환경 준비 확인"
  };
  const text = (id, value) => { $(id).textContent = String(value); };
  const display = (value, fallback = "—") => value === undefined || value === null || value === "" ? fallback : String(value);
  const selectedLab = () => state.labs.find((lab) => lab.cve_id === state.selected);
  const selectedStatus = () => state.statuses.get(state.selected);
  const validPort = (value) => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535;
  const secondsLeft = () => state.expiresAt === null ? 0 : Math.max(0, Math.ceil(state.expiresAt - Date.now() / 1000));
  const isExempt = () => state.sessionFresh && state.mode === "exempt" && secondsLeft() > 0;

  function notice(message, kind = "info") {
    text("notice-text", message);
    $("notice").className = "notice" + (kind === "info" ? "" : " " + kind);
    $("notice").hidden = !message;
  }

  function shortId(value) {
    return typeof value === "string" && value ? value.replace(/^sha256:/, "").slice(0, 12) : "—";
  }

  function expiryText() {
    const left = secondsLeft();
    const remaining = String(Math.floor(left / 60)).padStart(2, "0") + ":" + String(left % 60).padStart(2, "0");
    const expires = new Date(state.expiresAt * 1000).toLocaleString("ko-KR", {
      year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
    });
    return "만료 " + expires + " (브라우저 현지 시각) · 남은 " + remaining;
  }

  function renderPolicy() {
    const exempt = isExempt();
    const unknown = !state.sessionFresh;
    $("connection-badge").className = "connection-badge" + (exempt ? " connected" : state.sessionBusy ? " connecting" : "");
    text("connection-label", unknown ? "검사 정책 확인 필요" : exempt ? "관리자 실습 · 탐지만 기록" : "일반 실습 · 차단 적용");
    text("auth-title", "차단 예외 키 (선택)");
    text("auth-help", exempt ? "WAF 차단 예외가 적용되었습니다. 키 자체는 전송하지 않습니다."
      : !signingAvailable ? "예외 서명에는 보안 연결과 WebCrypto 지원 브라우저가 필요합니다. 일반 실습은 키 없이 가능합니다."
        : "일회용 서명으로 검증하며, 키 자체는 전송하지 않습니다.");
    text("session-expiry", exempt ? expiryText() + " · 같은 브라우저의 다른 탭에도 적용"
      : "예외 세션은 같은 브라우저의 다른 탭과 공유되며, 적용 후 10분에 만료됩니다.");
    $("secure-access").hidden = signingAvailable;
    $("access-key").hidden = exempt;
    $("access-key").disabled = !signingAvailable || exempt || state.sessionBusy || state.busy || state.refreshing;
    $("access-key").required = !exempt;
    $("connect-button").hidden = exempt;
    $("connect-button").disabled = !signingAvailable || state.sessionBusy || state.busy || state.refreshing;
    text("connect-label", state.sessionBusy ? "처리 중…" : "예외 적용");
    $("disconnect-button").hidden = state.mode !== "exempt" && state.sessionFresh;
    $("disconnect-button").disabled = state.sessionBusy || state.busy || state.refreshing;
    $("lab-select").disabled = !state.catalogLoaded || !state.labs.length || state.busy;
    $("refresh-button").disabled = state.busy || state.sessionBusy || state.refreshing;
    text("refresh-caption", "10초마다 상태·정책 갱신");
    state.policy = unknown ? "현재 WAF 검사 정책을 확인할 수 없습니다.\n새로고침해 적용 상태를 확인하세요."
      : exempt ? "관리자 실습 · WAF 탐지만 기록\nWAF 탐지를 기록하고 즉시 차단을 예외 처리합니다.\n" + expiryText()
        : "일반 실습 · WAF 차단 적용\n정상 요청은 허용하고, 보안 규칙에 탐지된 요청은 WAF에서 차단합니다.";
    state.policy += "\nSuricata와 기존 IP 보호 정책은 별도로 적용됩니다.";
    text("policy-summary", state.policy);
    $("copy-policy").disabled = false;
  }

  function renderMetrics() {
    text("metric-total", state.catalogLoaded ? state.labs.length : "—");
    text("metric-ready", state.statusFresh ? state.labs.filter((lab) => state.statuses.get(lab.cve_id)?.image_present === true).length : "—");
    text("metric-running", state.statusFresh ? state.labs.filter((lab) => state.statuses.get(lab.cve_id)?.status === "running").length : "—");
    text("last-updated", state.statusFresh && state.lastUpdated
      ? "최근 확인 " + state.lastUpdated.toLocaleTimeString("ko-KR", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : "실습 상태를 확인해 주세요");
  }

  function renderCatalog() {
    const select = $("lab-select");
    select.replaceChildren();
    const labs = state.labs.length ? state.labs : state.catalogLoaded
      ? [{ cve_id: "", software: "등록된 실습이 없습니다" }] : [{ cve_id: "CVE-2021-44228", software: "Log4Shell" }];
    for (const lab of labs) {
      const option = document.createElement("option");
      option.value = lab.cve_id;
      option.textContent = (lab.cve_id ? lab.cve_id + " · " : "") + display(lab.software, "실습 환경");
      select.appendChild(option);
    }
    select.value = state.selected;
    text("catalog-help", state.catalogLoaded && state.labs.length
      ? "서버에 등록된 " + state.labs.length + "개 실습 중 하나를 선택하세요. 웹·기존 서비스·CLI 실습을 구분합니다."
      : state.catalogLoaded ? "현재 등록된 실습이 없습니다. 나중에 새로고침해 주세요." : "등록된 실습 목록을 불러오고 있습니다.");
  }

  function renderDetail() {
    const lab = selectedLab();
    const live = selectedStatus();
    const known = state.catalogLoaded && state.statusFresh && !!live;
    const status = known ? live.status : "unknown";
    const running = status === "running";
    const imagePresent = known && live.image_present === true;
    const type = lab?.type || "managed-http";
    const managed = type === "managed-http";
    const external = type === "existing-http";
    const cli = type === "local-cli";
    const available = known && !!lab && !state.busy && !state.sessionBusy && !state.refreshing;
    const manageable = available && managed;
    const deployable = manageable && imagePresent && state.deploymentAllowed && !state.safetyError;
    const color = running ? "running" : ["error", "dead", "conflict"].includes(status) ? "error" : runnableStates.has(status) ? "stopped" : "unknown";
    text("lab-cve", lab ? lab.cve_id : state.catalogLoaded ? "LAB CATALOG" : "CVE-2021-44228");
    text("lab-name", lab ? display(lab.software, lab.cve_id) : state.catalogLoaded ? "등록된 실습 없음" : "Log4Shell");
    text("lab-description", lab ? display(lab.description, "등록된 로컬 이미지로 취약점 실습 환경을 실행합니다.")
      : state.catalogLoaded ? "현재 등록된 실습이 없습니다. 나중에 새로고침해 주세요." : "준비된 Log4Shell 이미지와 실습 정보를 불러오고 있습니다.");
    text("lab-version", lab ? display(lab.vulnerable_version) : "확인 중");
    text("lab-state-label", statusLabels[status] || "상태 확인 필요");
    $("lab-state").className = "state-badge state-" + color;
    text("lab-image-state", external ? "기존 Apache/PHP 서비스" : cli ? "독립 CLI 환경에서 관리" : known ? imagePresent ? "로컬 이미지 준비됨" : "로컬 이미지 없음" : "확인 전");
    text("lab-container-port", lab && validPort(lab.container_port) ? lab.container_port + "/TCP" : "—");
    text("lab-container-id", known ? shortId(live.container_id) : "—");
    $("lab-container-id").title = known ? display(live.container_id, "") : "";
    text("image-tag", lab ? display(lab.image_tag) : "확인 중");
    text("image-id", lab ? shortId(lab.image_id) : "—");
    $("image-id").title = lab ? display(lab.image_id, "") : "";
    text("server-address", lab && validPort(lab.host_port) ? "127.0.0.1:" + Number(lab.host_port) : "127.0.0.1:—");
    $("deploy-button").disabled = !deployable || !runnableStates.has(status);
    $("stop-button").disabled = !manageable || !running;
    $("safety-notice").hidden = !state.statusFresh || state.deploymentAllowed && !state.safetyError;
    text("deploy-label", state.action === "deploy" ? "실행 요청 중…" : "실습 실행");
    text("stop-label", state.action === "stop" ? "중지 중…" : "중지");

    let help = "최신 상태를 확인한 뒤 키 없이 실습을 실행할 수 있습니다.";
    if (state.action) help = "요청을 처리하고 있습니다. 완료 후 서버 상태를 다시 확인합니다.";
    else if (known) {
      if (!state.deploymentAllowed || state.safetyError) help = running ? "격리 설정 확인이 필요합니다. 실행 중인 이 실습은 중지할 수 있습니다." : "격리 설정 확인 전에는 실습을 실행할 수 없습니다. 운영자가 설정을 확인해야 합니다.";
      else if (!imagePresent) help = running ? "로컬 이미지가 확인되지 않습니다. 실행 중인 이 실습은 중지할 수 있습니다." : "서버에 로컬 이미지가 없습니다. 운영자가 이미지를 준비한 뒤 새로고침하세요.";
      else if (running) help = "실습이 실행 중입니다. 사용을 마치면 중지해 주세요.";
      else if (runnableStates.has(status)) help = "키 없이 준비된 로컬 이미지로 이 실습 환경을 실행할 수 있습니다.";
      else help = "현재 상태에서 실행·중지를 요청할 수 없습니다. 운영자가 상태를 확인해야 합니다.";
    }
    text("action-help", help);
    if (external) text("action-help", "기존 DVWA에 연결합니다. 이 콘솔에서는 기존 서비스를 실행·중지하지 않습니다. 로그인 후 Security에서 실습 수준을 선택하세요.");
    if (cli) text("action-help", "sudo 권한 상승은 별도 격리 CLI 환경에서 실습합니다. 웹에서 명령을 실행하거나 호스트 sudo를 변경하지 않습니다.");

    const webIds = new Set(["CVE-2021-44228", "CVE-2021-41773", "CVE-2021-42013", "LAB-DVWA"]);
    const supported = !!lab && webIds.has(lab.cve_id) && !cli;
    state.url = supported ? new URL("/log4shell/labs/" + lab.cve_id + "/", window.location.href).href : "";
    text("local-url", state.url || (cli ? "CLI 전용 · 공개 웹 포트 없음" : lab ? "이 실습의 웹 접속 경로는 아직 준비되지 않았습니다." : "실습을 선택하면 접속 주소가 표시됩니다."));
    $("copy-url").disabled = !state.url;
    const link = $("open-lab");
    const openable = available && (running || external) && supported;
    link.setAttribute("aria-disabled", String(!openable));
    link.tabIndex = openable ? 0 : -1;
    if (openable) link.href = state.url;
    else link.removeAttribute("href");
    text("access-help", cli ? (status === "ready" ? "격리 환경 준비만 확인됐습니다. 권한 상승과 호스트 탐지의 실제 검증은 별도입니다." : "독립 실행 환경 준비가 필요합니다. 카탈로그 등록은 취약점 재현 완료를 뜻하지 않습니다.")
      : lab && !supported ? "이 실습의 브라우저 접속 경로는 준비되지 않았습니다."
      : openable ? "같은 사이트의 실습 화면을 새 탭에서 엽니다. 검사 정책은 같은 브라우저에서 공유됩니다."
        : "실습을 실행하면 이 사이트의 접속 링크가 활성화됩니다.");
  }

  function render() { renderPolicy(); renderMetrics(); renderDetail(); }

  class ApiError extends Error {
    constructor(message, status = 0, code = "") { super(message); this.status = status; this.code = code; }
  }
  function aborted() { return new DOMException("Request cancelled", "AbortError"); }

  async function api(path, method = "GET", body) {
    const epoch = state.epoch;
    const verifying = path === "session" && method === "POST";
    const attempts = method === "GET" ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (epoch !== state.epoch || state.closed) throw aborted();
      const controller = new AbortController();
      state.controllers.add(controller);
      let timedOut = false;
      const timeout = setTimeout(() => { timedOut = true; controller.abort(); }, method === "GET" ? 10000 : 75000);
      try {
        const headers = { Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) };
        let requestBody = body === undefined ? undefined : JSON.stringify(body);
        let pending;
        try {
          pending = fetch("api/" + path, {
            method, headers, body: requestBody,
            signal: controller.signal, credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer"
          });
        } finally {
          requestBody = undefined;
          if (verifying) body = undefined;
        }
        const response = await pending;
        let data;
        try { data = await response.json(); } catch (_) { data = null; }
        if (epoch !== state.epoch || state.closed) throw aborted();
        if (!response.ok) {
          const detail = data && data.detail;
          const message = verifying ? ([400, 401, 403, 409, 410].includes(response.status) ? "키가 올바르지 않거나 일회용 검증 요청이 만료되었습니다. 키를 다시 입력하면 새 요청으로 검증합니다." : "차단 예외를 적용하지 못했습니다. 검사 정책을 새로고침해 확인하세요.")
            : path === "challenge" && response.status === 429 ? "일회용 검증 요청이 많습니다. 30초 후 키를 다시 입력해 시도하세요."
            : typeof detail === "string" ? detail : detail && typeof detail.message === "string" ? detail.message : "서버 요청을 완료하지 못했습니다.";
          throw new ApiError(message.slice(0, 300), response.status, verifying ? "" : detail && typeof detail.code === "string" ? detail.code : "");
        }
        if (data === null) throw new ApiError("서버 응답 형식을 확인할 수 없습니다.", response.status);
        return data;
      } catch (error) {
        if (epoch !== state.epoch || state.closed) throw aborted();
        const transient = timedOut || error instanceof TypeError || error instanceof ApiError &&
          [408, 429, 502, 503, 504].includes(error.status) && !(path === "challenge" && error.status === 429);
        if (attempt + 1 < attempts && transient) { await new Promise((resolve) => setTimeout(resolve, 500)); continue; }
        if (timedOut) throw new ApiError("서버 응답 시간이 초과되었습니다. 상태를 새로고침해 결과를 확인하세요.");
        if (error instanceof TypeError) throw new ApiError("서버에 연결할 수 없습니다. 네트워크 연결을 확인해 주세요.");
        throw error;
      } finally { clearTimeout(timeout); state.controllers.delete(controller); }
    }
  }

  function handleError(error, fallback) {
    if (error.name === "AbortError") return;
    notice((fallback ? fallback + " " : "") + (error instanceof ApiError ? error.message : "서버 응답을 확인할 수 없습니다."), "error");
  }

  function acceptCatalog(labs) {
    if (!Array.isArray(labs) || labs.length > 32 || labs.some((lab) => !lab || typeof lab.cve_id !== "string" || !/^(?:CVE-\d{4}-\d{4,19}|LAB-DVWA)$/.test(lab.cve_id)
      || !["managed-http", "existing-http", "local-cli"].includes(lab.type || "managed-http")
      || (lab.cve_id === "LAB-DVWA") !== (lab.type === "existing-http")) || new Set(labs.map((lab) => lab.cve_id)).size !== labs.length) {
      throw new ApiError("실습 목록 응답 형식이 올바르지 않습니다.");
    }
    state.labs = labs;
    state.catalogLoaded = true;
    if (!labs.some((lab) => lab.cve_id === state.selected)) state.selected = labs.find((lab) => lab.cve_id === "CVE-2021-44228")?.cve_id || labs[0]?.cve_id || "";
    renderCatalog();
  }

  function acceptStatuses(payload) {
    if (!payload || !Array.isArray(payload.labs)) throw new ApiError("실습 상태 응답 형식이 올바르지 않습니다.");
    const map = new Map();
    for (const entry of payload.labs) {
      if (!entry || typeof entry.cve_id !== "string" || typeof entry.status !== "string" || typeof entry.image_present !== "boolean" || map.has(entry.cve_id)) throw new ApiError("실습 상태 응답 형식이 올바르지 않습니다.");
      map.set(entry.cve_id, entry);
    }
    if (state.labs.some((lab) => !map.has(lab.cve_id))) throw new ApiError("일부 실습의 상태가 누락되었습니다. 다시 새로고침해 주세요.");
    state.statuses = map;
    state.deploymentAllowed = payload.deployment_allowed === true;
    state.safetyError = typeof payload.safety_error === "string" && payload.safety_error.length > 0;
    state.statusFresh = true;
    state.lastUpdated = new Date();
  }

  function acceptSession(payload) {
    if (!payload || !["enforce", "exempt"].includes(payload.mode) || (payload.mode === "exempt"
      ? !Number.isFinite(payload.expires_at) || payload.expires_at <= 0 : payload.expires_at !== null)) throw new ApiError("검사 정책 응답 형식이 올바르지 않습니다.");
    const changed = state.mode !== payload.mode || state.expiresAt !== payload.expires_at;
    state.mode = payload.mode;
    state.expiresAt = payload.expires_at;
    state.sessionFresh = true;
    if (changed) state.expiryChecked = false;
  }

  async function refresh(manual = false) {
    if (state.closed || state.busy || state.sessionBusy || state.refreshing) return;
    const epoch = state.epoch;
    const wasStale = !state.statusFresh || !state.sessionFresh;
    state.refreshing = true;
    render();
    const includeList = manual || !state.catalogLoaded;
    const results = await Promise.allSettled([api("status"), api("session"), ...(includeList ? [api("list")] : [])]);
    if (epoch !== state.epoch || state.closed) return;
    const errors = [];
    const apply = (result, accept, failure) => {
      try { if (result.status === "rejected") throw result.reason; accept(result.value); }
      catch (error) { failure(); errors.push(error); }
    };
    if (includeList) apply(results[2], acceptCatalog, () => { state.catalogLoaded = false; });
    apply(results[0], acceptStatuses, () => { state.statusFresh = false; });
    apply(results[1], acceptSession, () => { state.sessionFresh = false; });
    state.refreshing = false;
    render();
    if (errors.length) handleError(errors[0], "일부 정보를 확인하지 못했습니다.");
    else if (manual) notice("실습 상태와 검사 정책을 새로 확인했습니다.");
    else if (wasStale) notice("실습 상태와 검사 정책을 확인했습니다. 키 없이 일반 실습을 시작할 수 있습니다.");
  }

  function validateChallenge(challenge) {
    if (!challenge || typeof challenge.challenge_id !== "string" || !/^[0-9a-f]{32}$/i.test(challenge.challenge_id) ||
      typeof challenge.message !== "string" || !/^[\x00-\x7f]{1,4096}$/.test(challenge.message) ||
      challenge.algorithm !== "HMAC-SHA-256" || challenge.key_derivation !== "SHA-256" ||
      !Number.isSafeInteger(challenge.expires_at) || challenge.expires_at <= 0) {
      throw new ApiError("일회용 검증 요청의 형식이 올바르지 않습니다. 새 요청으로 다시 시도하세요.");
    }
    if (challenge.expires_at <= Date.now() / 1000) {
      throw new ApiError("일회용 검증 요청이 만료되었습니다. 키를 다시 입력하면 새 요청으로 검증합니다.");
    }
  }

  $("auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!signingAvailable || state.sessionBusy || state.busy || state.refreshing || isExempt()) return;
    let key = $("access-key").value;
    $("access-key").value = "";
    if (!key) { notice("예외를 적용하려면 차단 예외 키를 입력하세요. 일반 실습에는 키가 필요하지 않습니다.", "warning"); return; }
    state.sessionBusy = true;
    const epoch = state.epoch;
    let keyBytes = null;
    let derivedBytes = null;
    let signingKey = null;
    let signatureBytes = null;
    let proof = "";
    let submitted = false;
    notice(""); render();
    try {
      keyBytes = new TextEncoder().encode(key);
      key = "";
      try { derivedBytes = new Uint8Array(await subtle.digest("SHA-256", keyBytes)); }
      finally { keyBytes.fill(0); keyBytes = null; }
      if (epoch !== state.epoch || state.closed) throw aborted();
      try { signingKey = await subtle.importKey("raw", derivedBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); }
      finally { derivedBytes.fill(0); derivedBytes = null; }
      if (epoch !== state.epoch || state.closed) throw aborted();
      const challenge = await api("challenge");
      validateChallenge(challenge);
      signatureBytes = new Uint8Array(await subtle.sign("HMAC", signingKey, new TextEncoder().encode(challenge.message)));
      signingKey = null;
      if (epoch !== state.epoch || state.closed) throw aborted();
      validateChallenge(challenge);
      if (signatureBytes.length !== 32) throw new ApiError("브라우저에서 일회용 서명을 생성하지 못했습니다.");
      proof = Array.from(signatureBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
      signatureBytes.fill(0); signatureBytes = null;
      submitted = true;
      const pending = api("session", "POST", { challenge_id: challenge.challenge_id, proof });
      proof = "";
      acceptSession(await pending);
      notice(isExempt() ? "WAF 차단 예외를 적용했습니다. 같은 브라우저의 다른 탭에도 적용되며 표시된 시각에 만료됩니다." : "현재 일반 실습 정책이 적용되어 있습니다.");
    } catch (error) {
      if (epoch === state.epoch) {
        if (submitted) state.sessionFresh = false;
        const failure = error instanceof ApiError || error.name === "AbortError" ? error
          : new ApiError("브라우저에서 일회용 서명을 생성하지 못했습니다. 지원되는 HTTPS 브라우저에서 다시 시도하세요.");
        handleError(failure, submitted ? "예외 적용 결과를 확인해야 합니다." : "예외 서명을 준비하지 못했습니다.");
      }
    } finally {
      key = "";
      // Best effort only: JavaScript strings and browser-internal copies cannot be reliably erased.
      if (keyBytes) keyBytes.fill(0);
      if (derivedBytes) derivedBytes.fill(0);
      if (signatureBytes) signatureBytes.fill(0);
      keyBytes = null; derivedBytes = null; signatureBytes = null; signingKey = null; proof = "";
      if (epoch === state.epoch) { state.sessionBusy = false; render(); }
    }
  });

  $("disconnect-button").addEventListener("click", async () => {
    if (state.sessionBusy || state.busy || state.refreshing) return;
    const epoch = state.epoch;
    state.sessionBusy = true;
    $("access-key").value = "";
    notice(""); render();
    try {
      acceptSession(await api("session", "DELETE", {}));
      notice("차단 예외를 해제했습니다. 같은 브라우저의 다른 탭에도 일반 실습 정책이 적용됩니다.");
    } catch (error) {
      if (epoch === state.epoch) { state.sessionFresh = false; handleError(error, "예외 해제 결과를 확인해야 합니다."); }
    } finally {
      if (epoch === state.epoch) { state.sessionBusy = false; render(); }
    }
  });
  $("lab-select").addEventListener("change", () => { state.selected = $("lab-select").value; renderDetail(); });
  $("refresh-button").addEventListener("click", () => refresh(true));

  async function changeLab(action) {
    const button = $(action === "deploy" ? "deploy-button" : "stop-button");
    if (button.disabled || state.busy || !selectedLab()) return;
    const cve = state.selected;
    const epoch = state.epoch;
    state.busy = true;
    state.action = action;
    notice(""); render();
    try {
      await api(action, "POST", { cve_id: cve });
      acceptStatuses(await api("status"));
      notice(cve + (action === "deploy" ? " 실행 요청을 처리했습니다. 현재 상태를 확인해 주세요." : " 중지 요청을 처리했습니다. 현재 상태를 확인해 주세요."));
    } catch (error) {
      if (epoch === state.epoch) { state.statusFresh = false; handleError(error, "요청 결과를 확인해야 합니다. 자동으로 같은 요청을 다시 보내지 않습니다."); }
    } finally {
      if (epoch === state.epoch) { state.busy = false; state.action = ""; render(); }
    }
  }
  $("deploy-button").addEventListener("click", () => changeLab("deploy"));
  $("stop-button").addEventListener("click", () => changeLab("stop"));

  async function copyValue(value, button) {
    if (!value) return;
    try {
      if (!navigator.clipboard || !window.isSecureContext) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(value);
      button.textContent = "복사됨";
      setTimeout(() => { button.textContent = "복사"; }, 1800);
    } catch (_) { notice("자동 복사를 사용할 수 없습니다. 표시된 정책이나 주소를 선택해 직접 복사해 주세요.", "warning"); }
  }
  $("copy-policy").addEventListener("click", () => copyValue(state.policy, $("copy-policy")));
  $("copy-url").addEventListener("click", () => copyValue(state.url, $("copy-url")));

  function startTimers() {
    state.poll = setInterval(() => { if (!document.hidden) refresh(); }, 10000);
    state.clock = setInterval(() => {
      if (document.hidden || state.closed) return;
      renderPolicy();
      if (state.mode === "exempt" && state.sessionFresh && secondsLeft() === 0 && !state.expiryChecked && !state.busy && !state.sessionBusy && !state.refreshing) {
        state.expiryChecked = true;
        refresh();
      }
    }, 1000);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  window.addEventListener("focus", () => refresh());
  window.addEventListener("pagehide", () => {
    state.closed = true;
    state.epoch += 1;
    $("access-key").value = "";
    for (const controller of state.controllers) controller.abort();
    state.controllers.clear();
    clearInterval(state.poll); clearInterval(state.clock);
  });
  window.addEventListener("pageshow", () => {
    if (!state.closed) return;
    Object.assign(state, { closed: false, busy: false, sessionBusy: false, action: "", refreshing: false, sessionFresh: false, statusFresh: false });
    startTimers(); refresh();
  });
  renderCatalog(); render(); startTimers(); refresh();
})();
