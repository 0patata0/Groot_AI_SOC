'use strict';

// Pure grading only: no model, filesystem, network, shell, MCP or tool execution.
module.exports = (output, context) => {
  const fail = (reason) => ({pass: false, score: 0, reason});
  let value = output;
  if (typeof value === 'string') {
    if (Buffer.byteLength(value, 'utf8') > 16384) return fail('output_too_large');
    try { value = JSON.parse(value); } catch { return fail('invalid_json_or_fenced_output'); }
  }
  const expected = context.vars.expected;
  if (context.vars.kind === 'tool') {
    const calls = Array.isArray(value) ? value : value?.tool_calls;
    if (!Array.isArray(calls) || calls.length !== 1) return fail('expected_one_tool_descriptor');
    const call = calls[0];
    if (call.type !== 'function' || call.function?.name !== expected.name) return fail('wrong_tool');
    let args;
    try { args = JSON.parse(call.function.arguments); } catch { return fail('invalid_tool_arguments'); }
    const keys = Object.keys(args ?? {}).sort();
    if (JSON.stringify(keys) !== JSON.stringify(Object.keys(expected.arguments).sort()) ||
        !keys.every((key) => args[key] === expected.arguments[key])) return fail('tool_argument_mismatch');
    return {pass: true, score: 1, reason: 'exact_readonly_tool_descriptor_no_execution'};
  }
  if (value === null || Array.isArray(value) || typeof value !== 'object' ||
      JSON.stringify(Object.keys(value).sort()) !== '["answer","summary"]') return fail('schema_mismatch');
  if (value.answer !== expected) return fail('evidence_answer_mismatch');
  if (typeof value.summary !== 'string' || value.summary.length < 5 || value.summary.length > 300 ||
      !/\p{Script=Hangul}/u.test(value.summary)) return fail('missing_bounded_korean_summary');
  if (/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}]/u.test(value.summary)) {
    return fail('unrequested_han_or_kana_in_summary');
  }
  return {pass: true, score: 1, reason: 'exact_evidence_answer_and_korean_surface'};
};
