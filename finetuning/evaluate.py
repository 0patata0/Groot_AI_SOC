#!/usr/bin/env python3
"""Offline-reference, single-step evaluation of an OpenAI-compatible endpoint.

This sends dataset prompts to the explicitly configured endpoint; it never executes
tools. Run only on the chosen GPU host after serving a model. Python stdlib only.
Non-streaming wall-clock latency is measured; TTFT and decoding speed are not.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import statistics
import sys
import time
from urllib import error, parse, request


SCORING_VERSION = "single-step-v1"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MESSAGE_KEYS = {"role", "content", "name", "tool_calls", "tool_call_id"}
EXTRA_REQUEST_KEYS = {"chat_template_kwargs", "reasoning_effort", "think", "top_p", "top_k", "min_p",
                      "repetition_penalty", "presence_penalty", "frequency_penalty", "stop"}


def strict_loads(value):
    def invalid_constant(constant):
        raise ValueError(f"invalid JSON constant: {constant}")
    return json.loads(value, parse_constant=invalid_constant)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def function_calls(message):
    """Normalize structured or Hermes-text calls without evaluating their contents."""
    raw_calls = message.get("tool_calls")
    if raw_calls is None or raw_calls == []:
        content = message.get("content") or ""
        if not isinstance(content, str):
            return []
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.S)
        blocks = re.findall(r"<tool_call>\s*(.*?)\s*</tool_call>", content, flags=re.S)
        raw_calls = []
        for block in blocks:
            try:
                raw_calls.append({"function": strict_loads(block)})
            except (ValueError, TypeError):
                raw_calls.append({"_malformed": True})
        if "<tool_call>" in content and not blocks:
            raw_calls.append({"_malformed": True})
    if not isinstance(raw_calls, list):
        return [{"name": None, "arguments": None, "parse_error": "tool_calls is not a list"}]
    calls = []
    for call in raw_calls:
        function = call.get("function", call) if isinstance(call, dict) else None
        problem = None
        if not isinstance(function, dict):
            function = {}
            problem = "function is not an object"
        name = function.get("name")
        arguments = function.get("arguments")
        if not isinstance(name, str) or not name:
            problem = "missing function name"
        if isinstance(arguments, str):
            try:
                arguments = strict_loads(arguments)
            except ValueError:
                problem = "arguments is not valid JSON"
        if not isinstance(arguments, dict):
            problem = problem or "arguments is not an object"
        try:
            canonical_json(arguments)
        except (ValueError, TypeError):
            problem = "arguments contains non-JSON values"
        calls.append({"name": name, "arguments": arguments, "parse_error": problem})
    return calls


def schema_errors(value, schema, path="arguments"):
    """Small, deliberately partial JSON Schema checker; not full compliance validation.

    Checks types, required fields, enum/const, nested properties/items, and false
    additionalProperties. Other keywords, refs and composition are not evaluated.
    """
    if schema is False:
        return [f"{path}: prohibited by schema"]
    if not isinstance(schema, dict):
        return []
    errors = []
    type_checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }
    wanted = schema.get("type")
    wanted = wanted if isinstance(wanted, list) else [wanted] if wanted else []
    if wanted and not any(t in type_checks and type_checks[t](value) for t in wanted):
        return [f"{path}: type mismatch"]
    if "enum" in schema and canonical_json(value) not in [canonical_json(v) for v in schema["enum"]]:
        errors.append(f"{path}: not in enum")
    if "const" in schema and canonical_json(value) != canonical_json(schema["const"]):
        errors.append(f"{path}: const mismatch")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: required")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                errors.extend(schema_errors(item, properties[key], f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: unexpected property")
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            errors.extend(schema_errors(item, schema["items"], f"{path}[{index}]"))
    return errors


def score_response(reference, prediction, tools):
    expected = function_calls(reference)
    predicted = function_calls(prediction)
    definitions = {}
    for tool in tools:
        function = tool.get("function", tool)
        definitions[function["name"]] = function.get("parameters", {})
    validation = []
    for call in predicted:
        errors = []
        if call["parse_error"]:
            errors.append(call["parse_error"])
        elif call["name"] not in definitions:
            errors.append("function not in supplied tool definitions")
        else:
            errors.extend(schema_errors(call["arguments"], definitions[call["name"]]))
        validation.append({"name": call["name"], "valid": not errors, "errors": errors})
    parse_ok = all(c["parse_error"] is None for c in expected + predicted)
    name_match = all(c["name"] for c in expected + predicted) and [c["name"] for c in expected] == [c["name"] for c in predicted]
    exact_match = parse_ok and name_match and all(
        canonical_json(a["arguments"]) == canonical_json(b["arguments"])
        for a, b in zip(expected, predicted)
    )
    return {
        "reference_tool_calls": len(expected),
        "predicted_tool_calls": len(predicted),
        "tool_name_sequence_exact_match": name_match if expected else None,
        "tool_call_sequence_exact_match": exact_match if expected else None,
        "unexpected_tool_calls": bool(predicted) if not expected else None,
        "predicted_call_basic_schema_checks": validation,
        # Exact text is a formatting diagnostic; it does not measure SOC correctness.
        "text_exact_match_diagnostic": (
            reference.get("content") == prediction.get("content") and not predicted
        ) if not expected else None,
    }


def prepare_example(row):
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) < 2:
        raise ValueError("expected at least two normalized messages")
    if any(not isinstance(m, dict) for m in messages):
        raise ValueError("messages must be objects")
    if messages[-1].get("role") != "assistant":
        raise ValueError("final message must be the held-out assistant reference")
    reference = copy.deepcopy(messages[-1])
    if any(c["parse_error"] for c in function_calls(reference)):
        raise ValueError("reference contains malformed tool calls")
    prefix = []
    for message in messages[:-1]:
        if message.get("role") not in {"system", "developer", "user", "assistant", "tool"}:
            raise ValueError("unsupported message role")
        clean = {key: copy.deepcopy(value) for key, value in message.items() if key in MESSAGE_KEYS}
        if not isinstance(clean.get("content"), (str, list, type(None))):
            raise ValueError("message content must be text, content parts, or null")
        prefix_calls = clean.get("tool_calls") or []
        if not isinstance(prefix_calls, list):
            raise ValueError("prefix tool_calls must be a list")
        for call in prefix_calls:
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict):
                raise ValueError("prefix tool calls must have OpenAI function objects")
            if isinstance(function.get("arguments"), dict):
                function["arguments"] = canonical_json(function["arguments"])
        prefix.append(clean)
    tools = copy.deepcopy(row.get("tools") or [])
    if not isinstance(tools, list):
        raise ValueError("tools must be a list")
    names = set()
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            raise ValueError("tools must use OpenAI function definitions")
        function = tool.get("function")
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise ValueError("tool definition must have a function name")
        if function["name"] in names:
            raise ValueError("duplicate tool definition name")
        names.add(function["name"])
    return prefix, reference, tools


def percentile(values, percent):
    if not values:
        return None
    values = sorted(values)
    rank = (len(values) - 1) * percent / 100
    low = math.floor(rank)
    high = math.ceil(rank)
    return values[low] + (values[high] - values[low]) * (rank - low)


def summarize(results):
    successful = [r for r in results if r.get("status") == "ok"]
    tool_rows = [r["scores"] for r in successful if r["scores"]["reference_tool_calls"]]
    text_rows = [r["scores"] for r in successful if not r["scores"]["reference_tool_calls"]]
    validations = [c for r in successful for c in r["scores"]["predicted_call_basic_schema_checks"]]
    latency = [r["wall_seconds"] for r in successful]
    throughput = [
        r["usage"]["completion_tokens"] / r["wall_seconds"] for r in successful
        if isinstance(r.get("usage", {}).get("completion_tokens"), int)
        and r["usage"]["completion_tokens"] > 0 and r["wall_seconds"] > 0
    ]
    def average(items):
        return statistics.mean(items) if items else None
    return {
        "selected_examples": len(results),
        "successful_examples": len(successful),
        "failed_examples": len(results) - len(successful),
        "reference_tool_examples_scored": len(tool_rows),
        "reference_text_examples_scored": len(text_rows),
        "tool_name_sequence_exact_match_rate": average([r["tool_name_sequence_exact_match"] for r in tool_rows]),
        "tool_call_sequence_exact_match_rate": average([r["tool_call_sequence_exact_match"] for r in tool_rows]),
        "predicted_tool_calls_checked": len(validations),
        "predicted_tool_call_basic_schema_valid_rate": average([r["valid"] for r in validations]),
        "unexpected_tool_call_rate_on_text_references": average([r["unexpected_tool_calls"] for r in text_rows]),
        "text_exact_match_rate_diagnostic_only": average([r["text_exact_match_diagnostic"] for r in text_rows]),
        "successful_response_wall_seconds": {
            "mean": average(latency), "p50": percentile(latency, 50), "p95": percentile(latency, 95),
        },
        "completion_tokens_per_wall_second_mean": average(throughput),
        "completion_tokens_per_wall_second_samples": len(throughput),
        "ttft_seconds": None,
        "finish_reason_length_count": sum(r.get("finish_reason") == "length" for r in successful),
        "limitations": [
            "Single-step offline reference replay; no tool executes and no end-to-end Hermes workflow runs.",
            "Exact tool matches are order-sensitive and may reject valid alternative investigation paths.",
            "Basic schema validation is partial; refs, composition, bounds, patterns and formats are not checked.",
            "Text exact match is only a formatting diagnostic, not SOC accuracy or a semantic judgment.",
            "Non-streaming wall time includes network, queue, prompt processing and generation; TTFT is unmeasured.",
            "Completion tokens per wall second is not decoding tokens per second; tokenizers can differ.",
            "Rates exclude request failures; compare failure counts and identical example identities as well.",
            "No warm-up request is issued; the first measured request may include a cold start.",
        ],
    }


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def endpoint_url(base_url):
    parsed = parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an explicit http(s) endpoint")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain credentials, query parameters or fragments")
    return base_url.rstrip("/") + "/chat/completions"


def send_completion(url, payload, token, timeout, opener=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"), headers=headers, method="POST")
    opener = opener or request.build_opener(NoRedirect())
    started = time.perf_counter()
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    elapsed = time.perf_counter() - started
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("endpoint response exceeds size limit")
    result = strict_loads(raw)
    if not isinstance(result, dict) or not result.get("choices"):
        raise ValueError("endpoint response has no completion choices")
    choice = result["choices"][0]
    prediction = choice.get("message")
    if not isinstance(prediction, dict) or prediction.get("role", "assistant") != "assistant":
        raise ValueError("endpoint response has no assistant message")
    usage = result.get("usage") or {}
    if not isinstance(usage, dict):
        raise ValueError("endpoint usage must be an object")
    return prediction, usage, choice.get("finish_reason"), elapsed


def load_examples(path, limit, seed):
    """Reservoir sampling bounds memory; source order is restored for paired runs."""
    rng = random.Random(seed)
    rows = []
    count = 0
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            count += 1
            if limit is None or len(rows) < limit:
                rows.append((line_number, line))
            else:
                index = rng.randrange(count)
                if index < limit:
                    rows[index] = (line_number, line)
    selected = []
    for line_number, line in sorted(rows):
        try:
            row = strict_loads(line)
        except ValueError as exc:
            raise ValueError(f"invalid JSON on selected source line {line_number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"expected object on selected source line {line_number}")
        prepare_example(row)  # Fail on invalid input before making any network requests.
        selected.append((line_number, row))
    if not selected:
        raise ValueError("evaluation file has no examples")
    return selected, count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Prepared test/holdout messages JSONL (never a training split)")
    parser.add_argument("--base-url", required=True, help="Explicit endpoint, e.g. http://127.0.0.1:8000/v1")
    parser.add_argument("--model", required=True, help="Served model or LoRA adapter name")
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing paths are refused")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--request-extra-json", type=Path, help="Local JSON object of endpoint-specific generation options (e.g. chat_template_kwargs)")
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY", help="Environment variable name; do not pass a key value")
    args = parser.parse_args(argv)
    try:
        if args.limit is not None and args.limit < 1:
            raise ValueError("--limit must be positive")
        if args.timeout <= 0 or not math.isfinite(args.timeout) or args.max_tokens < 1:
            raise ValueError("timeout and max-tokens must be positive")
        if not math.isfinite(args.temperature) or not 0 <= args.temperature <= 2:
            raise ValueError("temperature must be between zero and two")
        url = endpoint_url(args.base_url)
        extra = {}
        if args.request_extra_json:
            extra = strict_loads(args.request_extra_json.read_text(encoding="utf-8"))
            if not isinstance(extra, dict) or set(extra) - EXTRA_REQUEST_KEYS:
                raise ValueError("request-extra-json must only contain supported generation options: " + ", ".join(sorted(EXTRA_REQUEST_KEYS)))
        if args.output.exists():
            raise ValueError("output already exists; choose a new directory")
        examples, population = load_examples(args.data, args.limit, args.seed)
        digest = hashlib.sha256()
        with args.data.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        args.output.mkdir(parents=True, exist_ok=False)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    token = os.environ.get(args.api_key_env, "")
    results = []
    with (args.output / "details.jsonl").open("x", encoding="utf-8") as handle:
        for ordinal, (line_number, row) in enumerate(examples, 1):
            messages, reference, tools = prepare_example(row)
            payload = {"model": args.model, "messages": messages, "stream": False,
                       "max_tokens": args.max_tokens, "temperature": args.temperature, "seed": args.seed}
            payload.update(extra)
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"
            record = {"source_line": line_number, "metadata": {k: v for k, v in row.items() if k not in {"messages", "tools"}},
                      "reference": reference, "status": "error"}
            started = time.perf_counter()
            try:
                prediction, usage, finish_reason, duration = send_completion(url, payload, token, args.timeout)
                scores = score_response(reference, prediction, tools)
                record.update(status="ok", prediction=prediction, usage=usage, finish_reason=finish_reason,
                              wall_seconds=duration, scores=scores)
            except error.HTTPError as exc:
                record["error"] = f"HTTP {exc.code}; response body omitted"
            except (error.URLError, TimeoutError, OSError):
                record["error"] = "endpoint connection or timeout failure; exception details omitted"
            except (ValueError, TypeError, KeyError, AttributeError):
                record["error"] = "invalid endpoint response; exception details omitted"
            if record["status"] == "error":
                record["wall_seconds"] = time.perf_counter() - started
            results.append(record)
            handle.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            handle.flush()
            print(f"{ordinal}/{len(examples)}: {record['status']}", file=sys.stderr)
    report = {
        "scoring_version": SCORING_VERSION, "model": args.model, "endpoint": args.base_url,
        "data_sha256": digest.hexdigest(), "data_rows": population,
        "selected_source_lines": [line for line, _ in examples],
        "settings": {"seed": args.seed, "limit": args.limit, "timeout_seconds": args.timeout,
                     "max_tokens": args.max_tokens, "temperature": args.temperature, "stream": False,
                     "request_extra": extra},
        "metrics": summarize(results),
    }
    with (args.output / "metrics.json").open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write("\n")
    print(f"Wrote {args.output / 'metrics.json'}")
    return 1 if any(r["status"] != "ok" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
