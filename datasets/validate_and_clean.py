#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_and_clean.py  —  Qwen3 Agentic-SOC 파인튜닝 코퍼스 정제/검증기
=====================================================================

하는 일 (요청 4번 항목: 중복 제거 · Qwen3 Tool Calling 포맷 통일 · 토큰 길이 분포 검증)

  1) 포맷 자동 감지: ShareGPT(conversations/from/value+tools) / OpenAI(messages) / SEVENLLM(instruction/input/output)
  2) 단일 Qwen3 입력형으로 통일:
        {"messages":[{role, content, (tool_calls)}], "tools":[...]|None, "source","id"}
     - 역할명 매핑  human->user, gpt->assistant, system->system, tool 유지
     - <tool_call>{...}</tool_call> 텍스트 -> assistant.tool_calls[].function{name, arguments(객체)}
     - tool_call JSON 정준화: 작은따옴표/ast-dict/args-first/stringified-args -> {"name":..,"arguments":{..}}
     - glaive2 등 시스템 스키마 설명문 불일치 자동 교정, 중복 <tools> 시스템 블록 제거
     - <tool_response>..</tool_response> 언랩 -> role:tool
  3) 중복 제거: 정규화된 messages(+tools 이름) 해시
  4) 유효성 검증: 역할 순서, tool_calls 이름 ∈ tools, placeholder/파싱불량 격리
  5) 토큰 길이 분포: p50/p90/p95/p99/max + 상한 초과 수
        --tokenizer 주면 transformers 로 Qwen 챗 템플릿 정확 계산, 없으면 문자수 기반 추정(라벨 명시)
  6) 산출: <out>/<name>.cleaned.jsonl (소스별) + <report> (JSON 통계)

의존성: 표준 라이브러리만 필수. transformers 는 --tokenizer 쓸 때만 선택적으로 사용.

사용 예:
  python validate_and_clean.py --root /capston/datasets/processed --out ./cleaned --report ./validate_report.json
  python validate_and_clean.py --inputs hermes_fc_v1.dedup.jsonl glaive_fc_v2.hermes.jsonl --root /capston/datasets/processed
  python validate_and_clean.py --root /capston/datasets/processed --tokenizer Qwen/Qwen3-8B --max-len 32768
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict

# processed/ 안에서 "학습용 대화/지시" 로 간주하는 기본 파일(플로우 CSV·원경보 AIT·knowledge·eval 제외)
DEFAULT_INPUTS = [
    "hermes_fc_v1.dedup.jsonl",
    "glaive_fc_v2.hermes.jsonl",
    "hermes_agent_traces.jsonl",
    "sevenllm_en.jsonl",
    "attacklm.permissive.jsonl",
]

ROLE_MAP = {"human": "user", "gpt": "assistant", "system": "system", "tool": "tool",
            "user": "user", "assistant": "assistant", "function": "tool", "observation": "tool"}

TOOL_CALL_RE = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL)
TOOL_RESP_RE = re.compile(r"<tool_response>\s*(.*?)\s*</tool_response>", re.DOTALL)
TOOLS_BLOCK_RE = re.compile(r"<tools>\s*(.*?)\s*</tools>", re.DOTALL)
FC_PREAMBLE_RE = re.compile(r"You are a function calling AI model\.")
# placeholder 예시(미치환 토큰) — 학습/파싱에서 제외해야 함
PLACEHOLDER_RE = re.compile(r"<(function-name|args-dict|tool-name|arguments)>")


# ----------------------------------------------------------------------------- IO
def iter_jsonl(path):
    with open(path, "r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield ln, json.loads(line)
            except json.JSONDecodeError as e:
                yield ln, {"__parse_error__": str(e)}


def sha1(obj) -> str:
    return hashlib.sha1(
        json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# -------------------------------------------------------------- tool_call 정준화
def normalize_toolcall_json(raw: str):
    """raw 문자열 -> (dict|None, was_fixed:bool).  dict = {"name":.., "arguments":{..}}"""
    s = raw.strip()
    if PLACEHOLDER_RE.search(s):
        return None, False
    obj = None
    # 1) 정상 JSON
    try:
        obj = json.loads(s)
    except Exception:
        # 2) 파이썬 dict 표기(작은따옴표 등)
        try:
            obj = ast.literal_eval(s)
        except Exception:
            return None, False
    if not isinstance(obj, dict):
        return None, False
    name = obj.get("name")
    args = obj.get("arguments", obj.get("args", {}))
    if name is None:
        return None, False
    # arguments 가 문자열이면 객체로 파싱(Qwen 파서는 객체 요구)
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except Exception:
            try:
                args = ast.literal_eval(args)
            except Exception:
                pass  # 못 풀면 문자열 유지(검증에서 플래그)
    canonical = {"name": name, "arguments": args if isinstance(args, (dict, list)) else args}
    # 원본이 이미 정준형(큰따옴표·name-first)이 아니면 fixed 로 표기
    was_fixed = not s.lstrip().startswith('{"name"')
    return canonical, was_fixed


def extract_tool_calls(text: str):
    """assistant 텍스트에서 tool_call 블록 추출 -> (잔여텍스트, [call..], n_fixed, n_bad)."""
    calls, n_fixed, n_bad = [], 0, 0
    for m in TOOL_CALL_RE.finditer(text):
        tc, fixed = normalize_toolcall_json(m.group(1))
        if tc is None:
            n_bad += 1
            continue
        calls.append({"type": "function", "function": tc})
        if fixed:
            n_fixed += 1
    residual = TOOL_CALL_RE.sub("", text).strip()
    return residual, calls, n_fixed, n_bad


def unwrap_tool_response(text: str) -> str:
    m = TOOL_RESP_RE.search(text)
    return m.group(1).strip() if m else text.strip()


# ------------------------------------------------------- 시스템/도구 블록 정규화
def normalize_system_schema_text(text: str) -> str:
    """glaive2 류의 스키마 안내문 불일치 교정: {'arguments':..,'name':..} -> {"name":..,"arguments":..}."""
    text = text.replace("{'arguments': <args-dict>, 'name': <function-name>}",
                        '{"name": <function-name>, "arguments": <args-dict>}')
    text = text.replace("{'name': <function-name>, 'arguments': <args-dict>}",
                        '{"name": <function-name>, "arguments": <args-dict>}')
    return text


def split_system_and_tools(system_text, tools_field, strip_preamble):
    """시스템에서 tools 를 분리. 반환 (정리된 system_text, tools(list|None))."""
    tools = None
    if tools_field:
        tools = _parse_tools(tools_field)
    # 시스템 안에 <tools> 가 있으면 tools 로 채택(필드가 없을 때) + 본문에서 제거(중복 주입 방지)
    m = TOOLS_BLOCK_RE.search(system_text or "")
    if m:
        if tools is None:
            tools = _parse_tools(m.group(1))
        if strip_preamble:
            # FC 서문(있으면 그 지점)부터, 없으면 <tools> 블록부터 끝까지 제거
            # (schema 안내문·중복 <tools> 를 통째로 버려 Qwen 템플릿의 tools 재주입과 충돌 방지)
            pre = FC_PREAMBLE_RE.search(system_text)
            start = pre.start() if pre else m.start()
            system_text = system_text[:start].strip()
    else:
        system_text = normalize_system_schema_text(system_text or "")
    return (system_text or "").strip(), tools


def _parse_tools(val):
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        s = val.strip()
        for parser in (json.loads, ast.literal_eval):
            try:
                out = parser(s)
                if isinstance(out, list):
                    return out
                if isinstance(out, dict):
                    return [out]
            except Exception:
                continue
    return None


# --------------------------------------------------------------- 포맷별 변환
def detect_format(obj):
    if "conversations" in obj and isinstance(obj["conversations"], list):
        return "sharegpt"
    if "messages" in obj and isinstance(obj["messages"], list):
        return "openai"
    if "instruction" in obj and "output" in obj:
        return "sevenllm"
    return "unknown"


def convert_sharegpt(obj, strip_preamble, keep_think):
    issues = Counter()
    tools_field = obj.get("tools")
    msgs = []
    sys_tools = None
    for turn in obj["conversations"]:
        role = ROLE_MAP.get(turn.get("from", ""), None)
        val = turn.get("value", "") or ""
        if role is None:
            issues["bad_role"] += 1
            continue
        if role == "system":
            sys_text, sys_tools = split_system_and_tools(val, tools_field, strip_preamble)
            if sys_text:
                msgs.append({"role": "system", "content": sys_text})
            continue
        if role == "tool":
            msgs.append({"role": "tool", "content": unwrap_tool_response(val)})
            continue
        if role == "assistant":
            if not keep_think:
                val = re.sub(r"<think>.*?</think>", "", val, flags=re.DOTALL).strip()
            residual, calls, nf, nb = extract_tool_calls(val)
            issues["toolcall_fixed"] += nf
            issues["toolcall_bad"] += nb
            m = {"role": "assistant", "content": residual}
            if calls:
                m["tool_calls"] = calls
            msgs.append(m)
            continue
        # user
        msgs.append({"role": "user", "content": val})
    tools = sys_tools if sys_tools is not None else _parse_tools(tools_field)
    return msgs, tools, issues


def convert_openai(obj, keep_think):
    issues = Counter()
    msgs = []
    for turn in obj["messages"]:
        role = ROLE_MAP.get(turn.get("role", ""), turn.get("role"))
        content = turn.get("content", "") or ""
        if role == "assistant" and not keep_think:
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        m = {"role": role, "content": content}
        if turn.get("tool_calls"):
            m["tool_calls"] = turn["tool_calls"]
        msgs.append(m)
    return msgs, _parse_tools(obj.get("tools")), issues


def convert_sevenllm(obj, keep_think):
    issues = Counter()
    # 대부분 문자열이지만 일부 레코드는 instruction/thought를 JSON 객체로 저장한다.
    # 검증을 중단하지 않고 내용은 JSON 텍스트로 보존한다.
    def as_text(value):
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    instr = as_text(obj.get("instruction")).strip()
    inp = obj.get("input")
    out = obj.get("output")
    thought = as_text(obj.get("thought")).strip()
    user = instr if not inp else f"{instr}\n\n{inp if isinstance(inp, str) else json.dumps(inp, ensure_ascii=False)}"
    if isinstance(out, (dict, list)):
        out = json.dumps(out, ensure_ascii=False)
    assistant = (f"<think>{thought}</think>\n{out}" if (keep_think and thought) else (out or ""))
    msgs = [{"role": "user", "content": user.strip()},
            {"role": "assistant", "content": assistant.strip()}]
    return msgs, None, issues


# --------------------------------------------------------------- 유효성 검증
def validate_messages(msgs, tools):
    """경미 결함 리스트 반환(치명 결함이면 'FATAL:' 접두)."""
    problems = []
    if not msgs:
        return ["FATAL:empty"]
    tool_names = set()
    if tools:
        for t in tools:
            fn = t.get("function", t) if isinstance(t, dict) else {}
            n = fn.get("name") if isinstance(fn, dict) else None
            if n:
                tool_names.add(n)
    roles = [m["role"] for m in msgs]
    # user/assistant 쌍 최소 1개
    if "assistant" not in roles:
        problems.append("FATAL:no_assistant")
    for i, m in enumerate(msgs):
        if m["role"] == "assistant":
            for c in m.get("tool_calls", []):
                name = c.get("function", {}).get("name")
                args = c.get("function", {}).get("arguments")
                if not isinstance(args, (dict, list)):
                    problems.append("args_not_object")
                if tool_names and name not in tool_names:
                    problems.append("unknown_tool")
        if m["role"] == "tool":
            # tool 턴은 직전에 assistant.tool_calls 가 있어야 자연스러움(경미)
            prev = msgs[i-1] if i > 0 else None
            if not (prev and prev["role"] == "assistant" and prev.get("tool_calls")):
                problems.append("orphan_tool_turn")
    return problems


# --------------------------------------------------------------- 토큰 길이
class LengthEstimator:
    def __init__(self, tokenizer_name=None):
        self.tok = None
        self.exact = False
        self.divisor = 3.6  # 추정용(영문+JSON 혼합 경험치)
        if tokenizer_name:
            try:
                from transformers import AutoTokenizer  # type: ignore
                self.tok = AutoTokenizer.from_pretrained(tokenizer_name, trust_remote_code=True)
                self.exact = True
            except Exception as e:
                print(f"[warn] tokenizer '{tokenizer_name}' 로드 실패 -> 문자수 추정 사용: {e}", file=sys.stderr)

    def count(self, messages, tools):
        if self.exact:
            try:
                ids = self.tok.apply_chat_template(
                    messages, tools=tools, tokenize=True, add_generation_prompt=False)
                return len(ids)
            except Exception:
                try:
                    text = self.tok.apply_chat_template(
                        messages, tools=tools, tokenize=False, add_generation_prompt=False)
                    return len(self.tok(text).input_ids)
                except Exception:
                    pass  # 템플릿 미지원 시 추정으로 폴백
        # 추정: 렌더 문자열 길이 / divisor
        buf = []
        if tools:
            buf.append(json.dumps(tools, ensure_ascii=False))
        for m in messages:
            buf.append(m.get("role", ""))
            buf.append(m.get("content", "") or "")
            for c in m.get("tool_calls", []) or []:
                buf.append(json.dumps(c, ensure_ascii=False))
        return int(len("".join(buf)) / self.divisor)


def percentiles(values, ps=(50, 90, 95, 99)):
    if not values:
        return {}
    s = sorted(values)
    out = {}
    for p in ps:
        k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
        out[f"p{p}"] = s[k]
    out["max"] = s[-1]
    out["mean"] = round(sum(s) / len(s), 1)
    return out


# --------------------------------------------------------------- 메인 처리
def process_file(path, source, est, args, seen_hashes, report):
    kept, out_rows = 0, []
    st = report["by_source"][source]
    for ln, obj in iter_jsonl(path):
        st["input"] += 1
        if "__parse_error__" in obj:
            st["json_error"] += 1
            continue
        fmt = detect_format(obj)
        st["fmt_" + fmt] += 1
        if fmt == "unknown":
            continue
        if fmt == "sharegpt":
            msgs, tools, issues = convert_sharegpt(obj, not args.keep_system_tools, args.keep_think)
        elif fmt == "openai":
            msgs, tools, issues = convert_openai(obj, args.keep_think)
        else:
            msgs, tools, issues = convert_sevenllm(obj, args.keep_think)
        for k, v in issues.items():
            st[k] += v
        problems = validate_messages(msgs, tools)
        fatal = [p for p in problems if p.startswith("FATAL")]
        for p in problems:
            st["problem_" + p] += 1
        if fatal and not args.keep_invalid:
            st["dropped_invalid"] += 1
            continue
        rec = {"messages": msgs, "source": source}
        if tools:
            rec["tools"] = tools
        if obj.get("id") is not None:
            rec["id"] = obj["id"]
        # 중복 제거 키: 역할+내용+툴콜 이름 (+도구 이름)
        dedup_obj = [[m["role"], m.get("content", ""),
                      [c["function"]["name"] for c in m.get("tool_calls", [])]] for m in msgs]
        if tools:
            dedup_obj.append(sorted(
                [ (t.get("function", t) or {}).get("name") for t in tools if isinstance(t, dict) ]
            ))
        h = sha1(dedup_obj)
        if h in seen_hashes:
            st["dup_removed"] += 1
            continue
        seen_hashes.add(h)
        # 토큰 길이
        n = est.count(msgs, tools)
        st["_lengths"].append(n)
        for L in args.max_len:
            if n > L:
                st["over_%d" % L] += 1
        out_rows.append(rec)
        kept += 1
    st["output"] = kept
    # 쓰기
    if out_rows and not args.dry_run:
        os.makedirs(args.out, exist_ok=True)
        base = os.path.splitext(os.path.basename(path))[0]
        dst = os.path.join(args.out, base + ".cleaned.jsonl")
        with open(dst, "w", encoding="utf-8") as f:
            for r in out_rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        st["out_file"] = dst
    return kept


def main():
    ap = argparse.ArgumentParser(description="Qwen3 Agentic-SOC 코퍼스 정제/검증기")
    ap.add_argument("--root", default=".", help="processed 디렉터리")
    ap.add_argument("--inputs", nargs="*", default=None, help="root 기준 상대 파일명(미지정 시 기본 학습셋)")
    ap.add_argument("--out", default="./cleaned", help="정제 결과 출력 디렉터리")
    ap.add_argument("--report", default="./validate_report.json", help="통계 리포트 경로")
    ap.add_argument("--tokenizer", default=None, help="정확 토큰 수용 HF 토크나이저(미지정 시 문자수 추정)")
    ap.add_argument("--max-len", type=int, nargs="*", default=[8192, 16384, 32768],
                    help="초과 건수를 셀 길이 상한들")
    ap.add_argument("--keep-think", action="store_true", help="<think> 블록 보존(기본 제거)")
    ap.add_argument("--keep-system-tools", action="store_true",
                    help="시스템의 <tools>/FC 서문 보존(기본: 제거하고 tools 필드로 분리)")
    ap.add_argument("--keep-invalid", action="store_true", help="치명 결함 샘플도 보존")
    ap.add_argument("--dry-run", action="store_true", help="파일 쓰지 않고 통계만")
    args = ap.parse_args()

    inputs = args.inputs if args.inputs else DEFAULT_INPUTS
    est = LengthEstimator(args.tokenizer)

    report = {
        "config": {"root": args.root, "tokenizer": args.tokenizer or "(char-estimate /%.1f)" % est.divisor,
                   "exact_tokens": est.exact, "max_len": args.max_len,
                   "keep_think": args.keep_think, "strip_system_tools": not args.keep_system_tools},
        "by_source": defaultdict(lambda: defaultdict(int)),
        "totals": {},
    }
    for src in inputs:
        report["by_source"][src]["_lengths"] = []  # list

    seen = set()
    grand_in = grand_out = 0
    for rel in inputs:
        path = os.path.join(args.root, rel)
        if not os.path.exists(path):
            print(f"[skip] 없음: {path}", file=sys.stderr)
            continue
        print(f"[proc] {path}", file=sys.stderr)
        process_file(path, rel, est, args, seen, report)
        st = report["by_source"][rel]
        grand_in += st.get("input", 0)
        grand_out += st.get("output", 0)

    # 길이 분포 요약 + _lengths 제거
    all_len = []
    for src, st in report["by_source"].items():
        lens = st.pop("_lengths", [])
        all_len += lens
        st["length"] = percentiles(lens)
    report["totals"] = {
        "input": grand_in, "output_after_dedup": grand_out,
        "unique_hashes": len(seen),
        "length_overall": percentiles(all_len),
        "exact_tokens": est.exact,
    }
    # defaultdict -> dict
    report["by_source"] = {k: dict(v) for k, v in report["by_source"].items()}

    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 콘솔 요약
    print("\n==== 요약 ====")
    print(f"입력 {grand_in} -> 정제/중복제거 후 {grand_out}  (고유 {len(seen)})")
    print(f"길이({'정확토큰' if est.exact else '문자추정'}): {report['totals']['length_overall']}")
    for src, st in report["by_source"].items():
        if st.get("input"):
            print(f"  - {src}: in={st['input']} out={st.get('output',0)} "
                  f"dup={st.get('dup_removed',0)} fixedTC={st.get('toolcall_fixed',0)} "
                  f"badTC={st.get('toolcall_bad',0)} unknownTool={st.get('problem_unknown_tool',0)} "
                  f"len={st.get('length',{})}")
    print(f"\n리포트: {args.report}")
    if not args.dry_run:
        print(f"정제본: {args.out}/*.cleaned.jsonl")


if __name__ == "__main__":
    main()
