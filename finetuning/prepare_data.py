#!/usr/bin/env python3
"""Prepare existing project corpora with Python's standard library only.

Format handling follows datasets/validate_and_clean.py, with stricter schema,
argument and dialogue validation. No model, tokenizer or training is loaded.
Character limits are character limits, NOT estimates of tokenizer lengths.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile


DEFAULT_INPUTS = (
    "hermes_fc_v1.dedup.jsonl", "glaive_fc_v2.hermes.jsonl",
    "hermes_agent_traces.jsonl", "sevenllm_en.jsonl", "attacklm.permissive.jsonl",
)
ATTACKLM_LICENSES = {
    "BSD-3-Clause", "Apache-2.0", "DRL-1.1", "MIT", "Public-Domain",
    "Apache-2.0 AND MIT AND BSD-3-Clause",
}
ROLE_MAP = {"human": "user", "gpt": "assistant", "function": "tool", "observation": "tool"}
TOOL_CALL = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.S)
TOOLS = re.compile(r"<tools>\s*(.*?)\s*</tools>", re.S)
THINK = re.compile(r"<think>.*?</think>", re.S)
VALID_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}


class Reject(ValueError):
    """A stable, content-free reason code for rejecting one source row."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def text_value(value):
    return value if isinstance(value, str) else ("" if value is None else canonical(value))


def prompt_hash(text):
    # Deliberately conservative: tool schema and response variations of the same
    # first user request stay together, even across different source corpora.
    return digest(" ".join(text.split()))


def parse_embedded(value, reason):
    if not isinstance(value, str):
        return value
    for parser in (json.loads, ast.literal_eval):
        try:
            return parser(value)
        except (ValueError, SyntaxError, TypeError, RecursionError):
            pass
    raise Reject(reason)


def check_schema(schema, root=False):
    """Validate the supported JSON Schema subset; reject unhandled constraints.

    Metadata keywords are retained. References and other validation constructs
    are rejected rather than incorrectly claiming that they were checked.
    """
    if not isinstance(schema, dict):
        raise Reject("invalid_tool_schema")
    unsupported = {"$ref", "$dynamicRef", "not", "if", "then", "else", "dependentSchemas",
                   "dependentRequired", "dependencies", "patternProperties", "propertyNames",
                   "unevaluatedProperties", "unevaluatedItems", "contains", "prefixItems"}
    if unsupported.intersection(schema):
        raise Reject("unsupported_schema_constraint")
    kind = schema.get("type")
    if kind is None and "properties" in schema:
        schema["type"] = kind = "object"
    kinds = kind if isinstance(kind, list) else [kind]
    if kind is not None and (not kinds or any(k not in VALID_TYPES for k in kinds)):
        raise Reject("invalid_tool_schema")
    if root and kind != "object":
        raise Reject("tool_parameters_not_object")
    if "properties" in schema:
        if not isinstance(schema["properties"], dict) or kind not in (None, "object"):
            raise Reject("invalid_tool_schema")
        for child in schema["properties"].values():
            check_schema(child)
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(k, str) for k in required):
        raise Reject("invalid_tool_schema")
    if any(k not in schema.get("properties", {}) for k in required):
        raise Reject("invalid_tool_schema")
    if "items" in schema:
        check_schema(schema["items"])
    for key in ("allOf", "anyOf", "oneOf"):
        if key in schema:
            if not isinstance(schema[key], list) or not schema[key]:
                raise Reject("invalid_tool_schema")
            for child in schema[key]:
                check_schema(child)
    extra = schema.get("additionalProperties", True)
    if isinstance(extra, dict):
        check_schema(extra)
    elif not isinstance(extra, bool):
        raise Reject("invalid_tool_schema")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise Reject("invalid_tool_schema")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (TypeError, re.error):
            raise Reject("invalid_tool_schema") from None
    for key in ("minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties"):
        if key in schema and (type(schema[key]) is not int or schema[key] < 0):
            raise Reject("invalid_tool_schema")
    for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"):
        if key in schema and (type(schema[key]) not in (int, float) or (key == "multipleOf" and schema[key] <= 0)):
            raise Reject("invalid_tool_schema")


def matches_schema(value, schema):
    kinds = schema.get("type")
    if isinstance(kinds, str):
        kinds = [kinds]
    matches = {
        "object": isinstance(value, dict), "array": isinstance(value, list),
        "string": isinstance(value, str), "integer": type(value) is int,
        "number": type(value) in (int, float), "boolean": type(value) is bool, "null": value is None,
    }
    if kinds and not any(matches[k] for k in kinds):
        return False
    if "enum" in schema and canonical(value) not in [canonical(v) for v in schema["enum"]]:
        return False
    if "const" in schema and canonical(value) != canonical(schema["const"]):
        return False
    for key in ("allOf", "anyOf", "oneOf"):
        if key in schema:
            count = sum(matches_schema(value, child) for child in schema[key])
            if (key == "allOf" and count != len(schema[key])) or (key == "anyOf" and count == 0) or (key == "oneOf" and count != 1):
                return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            return False
        for key, child in value.items():
            if key in properties and not matches_schema(child, properties[key]):
                return False
            if key not in properties:
                extra = schema.get("additionalProperties", True)
                if extra is False or (isinstance(extra, dict) and not matches_schema(child, extra)):
                    return False
        if len(value) < schema.get("minProperties", 0) or len(value) > schema.get("maxProperties", float("inf")):
            return False
    if isinstance(value, list):
        if "items" in schema and not all(matches_schema(v, schema["items"]) for v in value):
            return False
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", float("inf")):
            return False
        if schema.get("uniqueItems") and len({canonical(v) for v in value}) != len(value):
            return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
    if type(value) in (int, float):
        if value < schema.get("minimum", -float("inf")) or value > schema.get("maximum", float("inf")):
            return False
        if value <= schema.get("exclusiveMinimum", -float("inf")) or value >= schema.get("exclusiveMaximum", float("inf")):
            return False
        if "multipleOf" in schema and abs(value / schema["multipleOf"] - round(value / schema["multipleOf"])) > 1e-9:
            return False
    return True


def normalize_tools(raw):
    if raw is None or raw == "":
        return []
    raw = parse_embedded(raw, "unparseable_tools")
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise Reject("invalid_tool_schema")
    result, seen = [], set()
    for item in raw:
        if not isinstance(item, dict) or item.get("type", "function") != "function":
            raise Reject("invalid_tool_schema")
        fn = item.get("function", item)
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str) or not fn["name"].strip():
            raise Reject("invalid_tool_schema")
        if fn["name"] in seen:
            raise Reject("duplicate_tool_name")
        seen.add(fn["name"])
        if "description" in fn and not isinstance(fn["description"], str):
            raise Reject("invalid_tool_schema")
        check_schema(fn.get("parameters"), root=True)
        result.append({"type": "function", "function": fn})
    return result


def normalize_record(obj, source, line_number=1):
    if not isinstance(obj, dict):
        raise Reject("record_not_object")
    if source == "attacklm.permissive.jsonl" and obj.get("license") not in ATTACKLM_LICENSES:
        raise Reject("unapproved_record_license")
    if "instruction" in obj and "output" in obj:
        user = text_value(obj["instruction"]).strip()
        if obj.get("input"):
            user += "\n\n" + text_value(obj["input"])
        turns = [{"role": "user", "content": user}, {"role": "assistant", "content": text_value(obj["output"])}]
    else:
        turns = obj.get("messages", obj.get("conversations"))
    if not isinstance(turns, list) or not turns:
        raise Reject("missing_messages")
    raw_tools = obj.get("tools")
    for turn in turns:
        if not isinstance(turn, dict):
            raise Reject("invalid_message")
        if turn.get("role", turn.get("from")) == "system":
            content = turn.get("content", turn.get("value", "")) or ""
            if not isinstance(content, str):
                raise Reject("content_not_text")
            # Hermes explains the XML tag names with the literal empty example
            # "within <tools> </tools> XML tags" before the actual JSON block.
            # Empty illustrative blocks carry no schema and are not ambiguous.
            blocks = [block for block in TOOLS.findall(content) if block.strip()]
            if len(blocks) > 1:
                raise Reject("ambiguous_system_tools")
            if blocks:
                embedded = normalize_tools(blocks[0])
                if raw_tools:
                    if canonical(embedded) != canonical(normalize_tools(raw_tools)):
                        raise Reject("conflicting_tool_schemas")
                else:
                    raw_tools = blocks[0]
    tools = normalize_tools(raw_tools)
    schemas = {t["function"]["name"]: t["function"]["parameters"] for t in tools}
    messages, pending, old_ids = [], [], set()
    for index, turn in enumerate(turns):
        role = turn.get("role", turn.get("from"))
        role = ROLE_MAP.get(role, role)
        if role not in {"system", "user", "assistant", "tool"}:
            raise Reject("invalid_role")
        content = turn.get("content", turn.get("value", "")) or ""
        if not isinstance(content, str):
            raise Reject("content_not_text")
        if role == "system":
            if any(m["role"] != "system" for m in messages):
                raise Reject("misplaced_system")
            if TOOLS.search(content):
                start = content.find("You are a function calling AI model.")
                content = content[:start].strip() if start >= 0 else TOOLS.sub("", content).strip()
        if role == "assistant":
            content = THINK.sub("", content).strip()
        message = {"role": role, "content": content}
        if role != "tool" and pending:
            raise Reject("missing_tool_response")
        if turn.get("tool_calls") and role != "assistant":
            raise Reject("tool_calls_on_nonassistant")
        if role == "assistant":
            raw_calls = turn.get("tool_calls", []) or []
            if not isinstance(raw_calls, list):
                raise Reject("invalid_tool_call")
            tagged = TOOL_CALL.findall(content)
            if tagged and raw_calls:
                raise Reject("duplicate_call_encoding")
            if tagged:
                raw_calls = [parse_embedded(raw, "unparseable_tool_call") for raw in tagged]
                message["content"] = TOOL_CALL.sub("", content).strip()
            if "<tool_call>" in message["content"] or "</tool_call>" in message["content"]:
                raise Reject("unclosed_tool_call")
            calls = []
            for call_index, raw_call in enumerate(raw_calls):
                if not isinstance(raw_call, dict) or raw_call.get("type", "function") != "function":
                    raise Reject("invalid_tool_call")
                fn = raw_call.get("function", raw_call)
                if not isinstance(fn, dict):
                    raise Reject("invalid_tool_call")
                name = fn.get("name")
                if not isinstance(name, str) or name not in schemas:
                    raise Reject("undefined_tool")
                args = parse_embedded(fn.get("arguments", fn.get("args", {})), "unparseable_arguments")
                if not isinstance(args, dict):
                    raise Reject("arguments_not_object")
                if not matches_schema(args, schemas[name]):
                    raise Reject("arguments_schema_mismatch")
                call_id = f"call_{index}_{call_index}"
                original_id = raw_call.get("id")
                if original_id is not None:
                    if not isinstance(original_id, str) or original_id in old_ids:
                        raise Reject("invalid_call_id")
                    old_ids.add(original_id)
                pending.append((call_id, original_id, name))
                calls.append({"id": call_id, "type": "function", "function": {"name": name, "arguments": args}})
            if calls:
                message["tool_calls"] = calls
            elif not message["content"].strip():
                raise Reject("empty_assistant")
        if role == "tool":
            if not pending:
                raise Reject("orphan_tool_response")
            response_id, response_name = turn.get("tool_call_id"), turn.get("name")
            candidates = [p for p in pending if (response_id is None or response_id == p[1]) and (response_name is None or response_name == p[2])]
            if len(candidates) != 1:
                raise Reject("ambiguous_tool_response")
            matched = candidates[0]
            pending.remove(matched)
            message["tool_call_id"] = matched[0]
            message["name"] = matched[2]
            wrapper = re.fullmatch(r"\s*<tool_response>\s*(.*?)\s*</tool_response>\s*", content, re.S)
            if wrapper:
                message["content"] = wrapper.group(1)
        if role != "system" or content:
            messages.append(message)
    if not messages or messages[-1]["role"] != "assistant":
        raise Reject("no_terminal_assistant")
    dialogue = [m["role"] for m in messages if m["role"] != "system"]
    if not dialogue or dialogue[0] != "user":
        raise Reject("no_initial_user")
    if any(a == b and a in {"user", "assistant"} for a, b in zip(dialogue, dialogue[1:])):
        raise Reject("invalid_turn_order")
    if any(m["role"] == "user" and not m["content"].strip() for m in messages):
        raise Reject("empty_user")
    result = {"messages": messages, "tools": tools, "id": f"{source}:{line_number}", "source": source}
    provenance = {key: obj[key] for key in ("source", "source_uri", "license", "license_uri", "mitre_ids", "platforms", "_bucket", "_source", "_source_file") if key in obj}
    if obj.get("id") is not None:
        provenance["original_id"] = obj["id"]
    if provenance:
        result["provenance"] = provenance
    return result


def group_key(record):
    return prompt_hash(next(m["content"] for m in record["messages"] if m["role"] == "user"))


def split_for_group(group, seed, validation_ratio, test_ratio):
    point = int(digest([seed, group])[:16], 16) / 2**64
    if point < test_ratio:
        return "test"
    if point < test_ratio + validation_ratio:
        return "validation"
    return "train"


def eval_prompt_hashes(obj):
    if not isinstance(obj, dict):
        raise Reject("invalid_evaluation_record")
    values = [obj[k] for k in ("question", "prompt") if isinstance(obj.get(k), str) and obj[k].strip()]
    for turn in obj.get("messages", obj.get("conversations", [])):
        if turn.get("role", turn.get("from")) in ("user", "human"):
            values.append(text_value(turn.get("content", turn.get("value"))))
            break
    if "instruction" in obj:
        prompt = text_value(obj["instruction"]).strip()
        if obj.get("input"):
            prompt += "\n\n" + text_value(obj["input"])
        values.append(prompt)
    if isinstance(obj.get("prompt"), str) and obj.get("description"):
        values.append(obj["prompt"] + "\n\n" + text_value(obj["description"]))
    if not values:
        raise Reject("unrecognized_evaluation_prompt")
    return {prompt_hash(value) for value in values if value.strip()}


def read_jsonl(path, sha):
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            sha.update(raw)
            if not raw.strip():
                continue
            try:
                yield number, json.loads(raw), None
            except (ValueError, UnicodeError, RecursionError):
                yield number, None, "invalid_json"


def prepare(datasets_dir, output_dir, seed=42, max_chars=60000, max_per_source=5000,
            validation_ratio=0.05, test_ratio=0.05):
    datasets_dir, output_dir = Path(datasets_dir).resolve(), Path(output_dir).resolve()
    if max_chars <= 0 or max_per_source < 0 or min(validation_ratio, test_ratio) <= 0 or validation_ratio + test_ratio >= 1:
        raise ValueError("Require max_chars > 0, max_per_source >= 0, positive split ratios with sum < 1")
    if output_dir == datasets_dir or datasets_dir in output_dir.parents:
        raise ValueError("Output must be outside the source datasets directory")
    sources = [datasets_dir / "processed" / name for name in DEFAULT_INPUTS]
    evaluation = sorted((datasets_dir / "processed" / "eval").glob("*.jsonl"))
    if not evaluation:
        raise FileNotFoundError("Required evaluation exclusion files missing: processed/eval/*.jsonl")
    evaluation.append(datasets_dir / "raw" / "sevenllm" / "test.jsonl")
    for path in sources + evaluation:
        if not path.is_file():
            raise FileNotFoundError(f"Required source missing: {path}")
    manifest = {
        "format_version": 1,
        "config": {"seed": seed, "max_chars": max_chars, "max_per_source": max_per_source,
                   "validation_ratio": validation_ratio, "test_ratio": test_ratio,
                   "length_unit": "Unicode characters in canonical messages+tools JSON; not tokens",
                   "think_policy": "remove explicit think blocks; omit SEVENLLM thought field",
                   "group_policy": "whitespace-normalized first user prompt, across sources",
                   "sampling": "lowest SHA256(seed,source,conversation) per source before group split"},
        "inputs": {}, "evaluation_exclusion_inputs": {}, "outputs": {},
        "excluded_categories": ["raw alerts", "CSV flows", "knowledge", "reference", "evaluation", "unlisted sources"],
        "limitations": ["Exact normalized prompt overlap only; no semantic or scenario-level leakage guarantee",
                        "Public corpus held-out splits are not an independent SOC operational benchmark",
                        "No tokenizer loaded; training must reject overlength examples without truncating tool conversations",
                        "Retain datasets/README.md and original license notices for attribution"],
    }
    blocked = set()
    for path in evaluation:
        sha, count = hashlib.sha256(), 0
        for number, obj, error in read_jsonl(path, sha):
            if error:
                raise ValueError(f"Invalid exclusion JSON: {path.name}:{number}")
            try:
                blocked.update(eval_prompt_hashes(obj))
            except Reject as exc:
                raise ValueError(f"Invalid exclusion record: {path.name}:{number} ({exc})") from None
            count += 1
        manifest["evaluation_exclusion_inputs"][str(path.relative_to(datasets_dir))] = {"sha256": sha.hexdigest(), "rows": count}
    manifest["evaluation_exclusion_prompt_groups"] = len(blocked)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=output_dir.parent) as temporary:
        temporary = Path(temporary)
        database = sqlite3.connect(temporary / "records.sqlite")
        try:
            database.execute("CREATE TABLE records (conversation TEXT PRIMARY KEY, source TEXT, prompt TEXT, rank TEXT, data TEXT)")
            for path in sources:
                sha, counts, rejected = hashlib.sha256(), Counter(input_rows=0, eligible_unique_rows=0), Counter()
                for number, obj, error in read_jsonl(path, sha):
                    counts["input_rows"] += 1
                    if error:
                        rejected[error] += 1
                        continue
                    try:
                        record = normalize_record(obj, path.name, number)
                        payload = canonical({"messages": record["messages"], "tools": record["tools"]})
                        if len(payload) > max_chars:
                            raise Reject("over_max_chars")
                        group = group_key(record)
                        if group in blocked:
                            raise Reject("evaluation_prompt_overlap")
                        conversation = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                        rank = digest([seed, path.name, conversation])
                        cursor = database.execute("INSERT OR IGNORE INTO records VALUES (?,?,?,?,?)", (conversation, path.name, group, rank, canonical(record)))
                        if not cursor.rowcount:
                            raise Reject("duplicate_conversation")
                        counts["eligible_unique_rows"] += 1
                    except Reject as exc:
                        rejected[str(exc)] += 1
                    except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
                        rejected["malformed_record"] += 1
                database.commit()
                manifest["inputs"][path.name] = {"path": str(path.relative_to(datasets_dir)), "sha256": sha.hexdigest(),
                                               **dict(counts), "rejected": dict(sorted(rejected.items())), "split_rows": {"train": 0, "validation": 0, "test": 0}}
            database.execute("CREATE INDEX source_rank ON records(source, rank)")
            handles = {name: (temporary / f"{name}.jsonl").open("wb") for name in ("train", "validation", "test")}
            output_hashes = {name: hashlib.sha256() for name in handles}
            group_splits, total_counts = {}, Counter()
            try:
                for path in sources:
                    selected = 0
                    limit = max_per_source if max_per_source else -1
                    for group, data in database.execute("SELECT prompt,data FROM records WHERE source=? ORDER BY rank LIMIT ?", (path.name, limit)):
                        split = split_for_group(group, seed, validation_ratio, test_ratio)
                        assert group_splits.setdefault(group, split) == split, "Prompt group leakage"
                        raw = (data + "\n").encode("utf-8")
                        handles[split].write(raw)
                        output_hashes[split].update(raw)
                        manifest["inputs"][path.name]["split_rows"][split] += 1
                        selected += 1
                        total_counts[split] += 1
                    stats = manifest["inputs"][path.name]
                    stats["selected_rows"] = selected
                    stats["rejected"]["source_cap"] = stats.get("eligible_unique_rows", 0) - selected
            finally:
                for handle in handles.values():
                    handle.close()
            if not all(total_counts[name] for name in handles):
                raise ValueError("A split is empty; increase --max-per-source or supply a larger valid corpus")
            manifest["split_prompt_groups"] = dict(Counter(group_splits.values()))
            manifest["totals"] = {"input_rows": sum(s["input_rows"] for s in manifest["inputs"].values()),
                                  "selected_rows": sum(total_counts.values()), "split_rows": dict(total_counts), "cross_split_prompt_overlap": 0}
            for name in handles:
                manifest["outputs"][name] = {"path": f"{name}.jsonl", "rows": total_counts[name], "records": total_counts[name], "sha256": output_hashes[name].hexdigest()}
            (temporary / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            output_dir.mkdir(parents=True, exist_ok=True)
            for name in ["train.jsonl", "validation.jsonl", "test.jsonl", "manifest.json"]:
                (temporary / name).replace(output_dir / name)
        finally:
            database.close()
    return manifest


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--datasets-dir", type=Path, default=script_dir.parent / "datasets")
    parser.add_argument("--output-dir", type=Path, default=script_dir / "data")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-chars", type=int, default=60000)
    parser.add_argument("--max-per-source", type=int, default=5000, help="0 means all eligible rows")
    parser.add_argument("--validation-ratio", type=float, default=0.05)
    parser.add_argument("--test-ratio", type=float, default=0.05)
    args = parser.parse_args()
    try:
        manifest = prepare(**vars(args))
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Preparation failed: {exc}\n")
    print(json.dumps({"output_dir": str(args.output_dir.resolve()), "totals": manifest["totals"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
