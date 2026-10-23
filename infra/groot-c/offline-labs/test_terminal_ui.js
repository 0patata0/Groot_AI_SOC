"use strict";
// Exercise the actual selection renderer without a browser or extra packages.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "static/app.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "static/index.html"), "utf8");
const nodes = new Map();
for (const match of html.matchAll(/\bid="([^"]+)"/g)) {
  assert(!nodes.has(match[1]), "duplicate HTML id");
  nodes.set(match[1], {textContent: "", disabled: false, hidden: false,
    setAttribute(name, value) { this[name] = value; }, removeAttribute(name) { delete this[name]; }});
}
const $ = id => {
  assert(nodes.has(id), "renderer must use an existing HTML id: " + id);
  return nodes.get(id);
};
const state = {catalogLoaded: true, statusFresh: true, labs: [], statuses: new Map(),
  selected: "", busy: false, sessionBusy: false, refreshing: false,
  deploymentAllowed: false, safetyError: true, action: ""};
const context = vm.createContext({$, state, URL,
  window: {location: {href: "https://lab.example/log4shell/"}},
  ApiError: class extends Error {}, renderCatalog() {},
  text: (id, value) => { $(id).textContent = String(value); },
  display: (value, fallback = "—") => value === undefined || value === null || value === "" ? fallback : String(value),
  selectedLab: () => state.labs.find(lab => lab.cve_id === state.selected),
  selectedStatus: () => state.statuses.get(state.selected),
  shortId: value => typeof value === "string" && value ? value.replace(/^sha256:/, "").slice(0, 12) : "—",
  validPort: value => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535,
  statusLabels: {running: "실행 중", stopped: "중지됨", ready: "환경 준비 확인"},
  runnableStates: new Set(["stopped", "not_deployed"]),
});
const start = source.indexOf("  function renderDetail() {");
const end = source.indexOf("\n  function render()", start);
assert(start >= 0 && end > start);
vm.runInContext(source.slice(start, end), context);
const metricsStart = source.indexOf("  function renderMetrics() {");
const metricsEnd = source.indexOf("\n  function renderCatalog()", metricsStart);
assert(metricsStart >= 0 && metricsEnd > metricsStart);
vm.runInContext(source.slice(metricsStart, metricsEnd), context);
const catalogStart = source.indexOf("  function acceptCatalog(labs) {");
const catalogEnd = source.indexOf("\n  function acceptStatuses", catalogStart);
assert(catalogStart >= 0 && catalogEnd > catalogStart);
vm.runInContext(source.slice(catalogStart, catalogEnd), context);
function select(type, cve, status, allowed = true) {
  state.selected = cve;
  state.labs = [{type, cve_id: cve, software: "fixture", vulnerable_version: "test"}];
  state.statuses = new Map([[cve, {status, deployment_allowed: allowed, image_present: true, container_id: "a".repeat(12)}]]);
  vm.runInContext("renderDetail()", context);
}

for (const cve of ["CVE-2022-0543", "CVE-2017-7494", "CVE-2021-3156"]) {
  select("managed-terminal", cve, "not_deployed");
  assert.equal($("deploy-button").disabled, false, "terminal uses its own isolation result");
  assert.equal($("stop-button").disabled, true);
  assert.equal($("open-lab")["aria-disabled"], "true");
  assert.equal($("deploy-label").textContent, "실습 환경 시작");
  select("managed-terminal", cve, "running");
  assert.equal($("deploy-button").disabled, true);
  assert.equal($("stop-button").disabled, false);
  assert.equal($("open-label").textContent, "환경 열기");
  assert.equal($("open-lab").href, "https://lab.example/log4shell/terminal/" + cve + "/");
  assert.equal($("policy-block").hidden, true);
  if (cve === "CVE-2021-3156") {
    assert.match($("action-help").textContent, /한 번에 하나/);
    assert.match($("access-help").textContent, /5분.*30분/);
    assert.match($("access-help").textContent, /콘솔에서 환경을 시작/);
  }
  select("managed-terminal", cve, "running", false);
  assert.equal($("stop-button").disabled, false, "failed isolation must still allow stop");
  assert.equal($("open-lab")["aria-disabled"], "true");
  assert.equal($("open-lab").href, undefined);
}
vm.runInContext('acceptCatalog([{type: "managed-terminal", cve_id: "CVE-2021-3156"}])', context);
assert.equal(state.selected, "CVE-2021-3156", "sudo terminal catalog entry is accepted");
assert.throws(() => vm.runInContext('acceptCatalog([{type: "managed-terminal", cve_id: "CVE-2099-9999"}])', context));
select("managed-terminal", "CVE-2099-9999", "running");
assert.equal($("open-lab")["aria-disabled"], "true", "unregistered terminal IDs must not open");
assert.equal(state.url, "");
select("local-cli", "CVE-2021-3156", "ready");
assert.equal($("deploy-button").disabled, true);
assert.equal($("stop-button").disabled, true);
assert.equal($("open-lab")["aria-disabled"], "true");
assert.equal(state.url, "");
state.deploymentAllowed = true;
state.safetyError = false;
select("managed-http", "CVE-2021-44228", "running");
assert.equal($("open-lab").href, "https://lab.example/log4shell/labs/CVE-2021-44228/");
assert.equal($("policy-block").hidden, false);
assert.equal($("open-label").textContent, "실습 열기");
state.labs = ["CVE-2021-44228", "CVE-2021-41773", "CVE-2021-42013", "CVE-2022-0543", "CVE-2017-7494", "CVE-2021-3156"]
  .map(cve_id => ({cve_id}));
state.statuses = new Map(state.labs.map(lab => [lab.cve_id, {image_present: true, status: "not_deployed"}]));
vm.runInContext("renderMetrics()", context);
assert.equal($("metric-total").textContent, "6");
assert.equal($("metric-ready").textContent, "6", "all six prepared images, including rootless sudo, are counted");
state.statuses.get("CVE-2021-3156").image_present = false;
vm.runInContext("renderMetrics()", context);
assert.equal($("metric-ready").textContent, "5", "unavailable images must not be counted ready");
console.log("terminal selection UI: PASS (3 terminals, image counts, independent guard, CLI and HTTP boundaries)");
