'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const grade = require('./grade.cjs');
const read = name => JSON.parse(fs.readFileSync(path.join(__dirname, name), 'utf8'));
let passed = 0;
const check = (output, vars, expected) => { assert.equal(grade(output, {vars}).pass, expected); passed++; };
const quality = read('quality.json'), tools = read('tools.json');
for (const test of quality.tests) {
  check(JSON.stringify({answer:test.vars.expected,summary:'제공된 관측 근거로 판단했습니다.'}), test.vars, true);
  check(JSON.stringify({answer:'wrong',summary:'관측 결과를 확인했습니다.'}), test.vars, false);
}
const q = quality.tests[0].vars;
for (const output of ['```json\n{}\n```','{}','null','[]','false',
  JSON.stringify({answer:q.expected,summary:'確認했습니다.'}),
  JSON.stringify({answer:q.expected,summary:'確認'}),
  JSON.stringify({answer:q.expected,summary:'English only'}),
  JSON.stringify({answer:q.expected,summary:'한국어로 답합니다.',extra:'ignored'}),
  JSON.stringify({answer:q.expected,summary:'한'.repeat(301)})]) check(output,q,false);
for (const test of tools.tests) {
  const call={type:'function',function:{name:test.vars.expected.name,arguments:JSON.stringify(test.vars.expected.arguments)}};
  check([call],test.vars,true);
  check(JSON.stringify([call]),test.vars,true);
  check({content:'상태를 조회하겠습니다.',tool_calls:[call]},test.vars,true);
  check([call,call],test.vars,false);
  check([{...call,function:{...call.function,name:'propose_service_action'}}],test.vars,false);
  check([{...call,function:{...call.function,arguments:'{"target":"a:waf","command":"restart"}'}}],test.vars,false);
}
for (const suite of [quality,tools]) {
  assert.equal(suite.providers.length,1);
  const p=suite.providers[0];
  assert.equal(p.id,'openai:chat:qwen3.6:35b');
  assert.equal(p.config.apiBaseUrl,'http://211.170.162.111:11434/v1');
  assert.equal(p.config.maxRetries,0);
  assert.equal(p.config.useDefaultApiKey,false);
  assert.equal(suite.evaluateOptions.maxConcurrency,1);
  assert.equal(suite.evaluateOptions.repeat,1);
  assert.equal(suite.sharing,false);
  assert.equal(suite.writeLatestResults,false);
  assert.ok(!('mcp' in p.config) && !('functionToolCallbacks' in p.config));
  assert.deepEqual(suite.defaultTest.assert.map(a=>a.type),['javascript','latency']);
  passed++;
}
assert.equal(quality.tests.length+tools.tests.length,8);
console.log(JSON.stringify({status:'passed',checks:passed,model_calls:0,tool_calls:0,packages_installed:0}));
