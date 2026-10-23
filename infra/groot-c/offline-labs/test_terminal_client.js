"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const P = require("./static/terminal.js");
const tick = () => new Promise(resolve => setImmediate(resolve));

async function protocolTests() {
  assert.deepEqual(P.dimensions(999, 0), {cols: 300, rows: 24});
  assert.deepEqual(P.dimensions(1, 1), {cols: 20, rows: 2});
  const utf8 = new TextEncoder().encode("한글🙂\u001b[31m<data>");
  assert.deepEqual(P.outputBytes(P.base64(utf8)), utf8);
  for (const invalid of ["A", "AA=A", "AAAA\n", "_w==", "a".repeat(262148), null]) {
    assert.throws(() => P.outputBytes(invalid));
  }
  for (const value of [{data: "", cursor: 1, truncated: false, closed: false},
                       {data: "", cursor: 2, truncated: 1, closed: false},
                       {data: "", cursor: Number.MAX_SAFE_INTEGER + 1, truncated: false, closed: false}]) {
    assert.throws(() => P.pollResult(value, 2));
  }
  const valid = P.pollResult({data: P.base64(utf8), cursor: 20, truncated: true, closed: false}, 2);
  assert.deepEqual(valid.bytes, utf8);
  assert.equal(valid.truncated, true);

  const sent = [];
  let release;
  const queue = new P.InputQueue(data => {
    sent.push(P.outputBytes(data));
    return new Promise(resolve => { release = resolve; });
  }, () => { throw new Error("unexpected failure"); });
  const bytes = new Uint8Array(5000).map((_, index) => index % 251);
  assert(queue.push(bytes));
  assert.equal(sent.length, 1, "only one input can be in flight");
  assert.equal(sent[0].length, 2048);
  release(); await tick();
  assert.equal(sent.length, 2);
  release(); await tick();
  assert.equal(sent.length, 3);
  release(); await tick();
  const complete = Uint8Array.from(sent.flatMap(chunk => Array.from(chunk)));
  assert.deepEqual(complete, bytes);
  assert.equal(queue.size, 0);
  assert.equal(queue.push(new Uint8Array(16385)), false);
  queue.stop();
  assert.equal(queue.push(new Uint8Array([1])), false);
  let failures = 0, writes = 0;
  const uncertain = new P.InputQueue(async () => { writes += 1; throw new Error("private server diagnostic"); }, () => { failures += 1; });
  uncertain.push(new Uint8Array(5000)); await tick();
  assert.equal(failures, 1);
  assert.equal(writes, 1, "uncertain commands must never retry");
  assert.equal(uncertain.size, 0);
  assert.deepEqual(await P.readJson(new Response('{"ok":true}')), {ok: true});
  await assert.rejects(P.readJson(new Response("x".repeat(393217))));
}

async function browserTests(cve, label, closeFails = false) {
  const html = fs.readFileSync(path.join(__dirname, "static/terminal.html"), "utf8");
  const documentReferrerPolicy = html.match(/<meta name="referrer" content="([^"]+)"/)[1];
  assert.equal(documentReferrerPolicy, "no-referrer");
  const nodes = new Map();
  for (const match of html.matchAll(/\bid="([^"]+)"/g)) {
    assert(!nodes.has(match[1]));
    nodes.set(match[1], {textContent: "", dataset: {}, events: {}, addEventListener(name, fn) { this.events[name] = fn; }});
  }
  const calls = [], outputs = [], timers = [], handlers = new Map(), listeners = new Map();
  let instance, releasePoll;
  let opens = 0, restartedFromConsole = false;
  const sudoLab = cve === "CVE-2021-3156";
  class Terminal {
    constructor(options) { this.options = options; this.parser = {registerOscHandler: (number, handler) => handlers.set(number, handler)}; instance = this; }
    loadAddon() {} open() {} resize(cols, rows) { this.cols = cols; this.rows = rows; }
    reset() {} focus() {} onData(fn) { this.data = fn; } onBinary(fn) { this.binary = fn; }
    write(bytes, done) { outputs.push(new Uint8Array(bytes)); done(); }
  }
  class FitAddon { proposeDimensions() { return {cols: 96, rows: 28}; } }
  const id = "a".repeat(64);
  async function fetch(url, options) {
    calls.push({url, options});
    // Fetch Standard 3.2: a non-CORS POST inheriting no-referrer sends
    // Origin:null, which this API correctly rejects. Model that browser
    // behavior instead of accepting every request in the fixture.
    const policy = options.referrerPolicy || documentReferrerPolicy;
    if (options.mode !== "cors" && policy === "no-referrer") {
      return new Response('{"detail":"origin_denied"}', {status: 403});
    }
    const operation = url.split("/").at(-1);
    if (operation === "open") {
      opens += 1;
      if (sudoLab && opens > 1 && !restartedFromConsole) return new Response('{"detail":"terminal_not_running"}', {status: 409});
      return new Response(JSON.stringify({session_id: id, expires_in: 600}));
    }
    if (operation === "poll") return new Promise(resolve => { releasePoll = resolve; });
    if (operation === "close" && closeFails) return new Response('{"detail":"close_failed"}', {status: 500});
    return new Response('{"ok":true}');
  }
  const window = {Terminal, FitAddon: {FitAddon}, location: {pathname: "/log4shell/terminal/" + cve + "/"},
    addEventListener: (name, fn) => listeners.set(name, fn)};
  const context = vm.createContext({window, document: {
    getElementById: id => { assert(nodes.has(id), id); return nodes.get(id); },
    documentElement: {getAttribute: () => "light"},
  }, fetch, MutationObserver: class {observe() {}}, ResizeObserver: class {observe() {}},
  TextEncoder, TextDecoder, Uint8Array, AbortController, btoa, atob,
  setTimeout: (fn, ms) => { timers.push(ms); return setTimeout(fn, ms); }, clearTimeout});
  vm.runInContext(fs.readFileSync(path.join(__dirname, "static/terminal.js"), "utf8"), context);
  await tick(); await tick();
  if (label === null) {
    assert.equal(nodes.get("terminal-status").textContent, "터미널을 준비할 수 없습니다");
    assert.equal(calls.length, 0, "unregistered CVEs cannot make terminal requests");
    assert.equal(instance, undefined);
    return;
  }
  assert.equal(nodes.get("terminal-status").textContent, "연결됨");
  assert.equal(nodes.get("terminal-title").textContent, label + " 터미널");
  assert.equal(context.document.title, label + " 터미널 · Lab Console");
  const opening = calls.find(call => call.url.endsWith("/open"));
  assert.deepEqual(JSON.parse(opening.options.body), {cve_id: cve, cols: 96, rows: 28},
    "client sends only the fixed lab ID and dimensions, without user or Docker parameters");
  assert.equal(instance.options.theme.background, "#f5f3ee");
  assert.equal(nodes.get("terminal-reconnect").disabled, sudoLab);
  assert.match(nodes.get("terminal-notice").textContent, sudoLab ? /실습 환경도 중지/ : /환경을 중지하지 않습니다/);
  if (sudoLab) {
    assert.match(nodes.get("terminal-notice").textContent, /실습 환경도 중지/);
    assert.match(nodes.get("terminal-notice").textContent, /5분.*30분/);
    nodes.get("terminal-reconnect").events.click(); await tick();
    assert.equal(opens, 1, "an active sudo session cannot reconnect and stop its environment");
  }
  assert.equal(handlers.get(52)(), true, "remote clipboard OSC must be intercepted");
  assert.equal(handlers.get(8)(), true, "output hyperlinks must be intercepted");
  const input = "한글".repeat(400);
  instance.data(input); await tick(); await tick();
  const inputCalls = calls.filter(call => call.url.endsWith("/input"));
  assert.equal(inputCalls.length, 2);
  const joined = Uint8Array.from(inputCalls.flatMap(call => {
    const body = JSON.parse(call.options.body);
    assert.equal(body.session_id, id);
    const bytes = P.outputBytes(body.data);
    assert(bytes.length <= 2048);
    return Array.from(bytes);
  }));
  assert.equal(new TextDecoder().decode(joined), input);
  let rejected = 0;
  nodes.get("terminal-screen").events.paste({clipboardData: {getData: () => "한".repeat(3000)},
    preventDefault() { rejected += 1; }, stopImmediatePropagation() { rejected += 1; }});
  assert.equal(rejected, 2);
  releasePoll(new Response(JSON.stringify({data: P.base64(new TextEncoder().encode("<img onerror=alert(1)>\u001b]52;c;AAAA\u0007")),
    cursor: 45, truncated: false, closed: true})));
  await tick(); await tick();
  assert.equal(outputs.length, 1);
  assert(outputs[0] instanceof Uint8Array);
  assert.equal(nodes.get("terminal-status").textContent, "연결 종료됨");
  assert(calls.some(call => call.url.endsWith("/close")));
  assert(timers.includes(sudoLab ? 30000 : 8000), "sudo close waits for whole-container stop");
  assert.match(nodes.get("terminal-notice").textContent, closeFails
    ? /종료 결과를 확인하지 못했습니다.*sudo 환경도 중지/
    : sudoLab ? /sudo 실습 환경이 종료됐습니다.*콘솔에서 환경을 시작/
      : /실습 환경은 콘솔에서 중지/);
  // pagehide uses a separate keepalive fetch; verify a live session also
  // closes with a non-null Origin instead of waiting for server expiry.
  nodes.get("terminal-reconnect").events.click();
  await tick(); await tick();
  if (sudoLab) {
    assert.equal(nodes.get("terminal-status").textContent, "연결할 수 없습니다");
    assert.match(nodes.get("terminal-notice").textContent, /다시 시작한 뒤 연결/);
    assert(!calls.some(call => call.url.endsWith("/deploy")), "reconnect must never start an environment");
    restartedFromConsole = true;
    nodes.get("terminal-reconnect").events.click();
    await tick(); await tick();
  }
  assert.equal(nodes.get("terminal-status").textContent, "연결됨");
  listeners.get("pagehide")();
  releasePoll(new Response(JSON.stringify({data: "", cursor: 0, truncated: false, closed: true})));
  await tick(); await tick();
  assert(calls.some(call => call.url.endsWith("/close") && call.options.keepalive === true));
  for (const call of calls) {
    assert(!call.url.includes(id), "session IDs stay out of URLs");
    assert.equal(call.options.method, "POST");
    assert.equal(call.options.credentials, "same-origin");
    assert.equal(call.options.mode, "same-origin");
    assert.equal(call.options.referrerPolicy, "strict-origin");
    assert(!("Authorization" in call.options.headers));
  }
}

(async () => {
  await protocolTests();
  for (const [cve, label] of [["CVE-2022-0543", "Redis"], ["CVE-2017-7494", "Samba"], ["CVE-2021-3156", "sudo"], ["CVE-2099-9999", null]]) {
    await browserTests(cve, label);
  }
  await browserTests("CVE-2021-3156", "sudo", true);
  console.log("terminal client: PASS (3 labs, bounded bytes, input order, no retry, lifecycle, OSC, same-origin)");
})().catch(error => { console.error(error); process.exitCode = 1; });
