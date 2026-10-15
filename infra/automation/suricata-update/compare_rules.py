#!/usr/bin/env python3
"""Pure comparison. Reuse the approved worker's parser, never its executor.

No Docker, network, rules publication or service operations. A successful match
means the active highest-revision rule bodies are equal, not byte-identical files
or an authorization to change the worker's ET+local concatenation contract.
"""
import ast
import hashlib
import re
import types

WORKER_SHA256 = "d937c7def4d2938d7655e445cb5cf9cd7858837aebebaf4278feae5fb69965a2"
FUNCTIONS = {"_suricata_lines", "_suricata_rule", "_suricata_number",
             "_validate_suricata_overrides"}
NATIVE_RULE_SHA256 = "c64bea79d98130fbbf489cd2d64ae7d80a38b98b7a8cdcd930381fe18b824046"


def native_parser(source):
    if hashlib.sha256(source).hexdigest() != NATIVE_RULE_SHA256:
        raise ValueError("native_parser_source_changed")
    module = types.ModuleType("capstone_pinned_update_rule")
    exec(compile(source, "installed-suricata-update-rule.py", "exec"), module.__dict__)
    return module


def native_active_map(data, module, duplicates_allowed):
    if not data or len(data) > 64 * 1024 * 1024 or b"\0" in data or b"\r" in data:
        raise ValueError("rule_bytes_invalid")
    lines = data.decode("utf-8", "strict").splitlines()
    result, duplicates, pending = {}, [], ""
    for line in lines:
        if not pending and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not pending and line[:1].isspace():
            raise ValueError("active_rule_indented")
        # This exactly follows the installed parse_fileobj continuation rule,
        # while rejecting active parse failures rather than silently skipping.
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        logical, pending = pending + line, ""
        parsed = module.parse(logical)
        if parsed is None or not parsed.enabled:
            raise ValueError("native_active_rule_parse_failed")
        gid, sid, rev = parsed.gid, parsed.sid, parsed.rev
        if any(type(n) is not int or not 0 < n < 2**32 for n in (gid, sid, rev)):
            raise ValueError("native_rule_number_invalid")
        key = (gid, sid)
        # The native parser already joins continuations and extracts raw. Do
        # not introduce another quote grammar for the complete ET language.
        # Internal whitespace remains exact: harmless reformatting may reject.
        body = parsed.raw.strip()
        if key in result:
            if not duplicates_allowed or gid != 1 or sid not in (2034802, 2034806):
                raise ValueError("unexpected_duplicate_sid")
            if rev == result[key][0]:
                raise ValueError("ambiguous_equal_revision")
            duplicates.append(sid)
        if key not in result or rev > result[key][0]:
            result[key] = (rev, body)
    if pending or not result:
        raise ValueError("incomplete_or_empty_rules")
    return result, sorted(duplicates)


def parser(worker_bytes):
    if hashlib.sha256(worker_bytes).hexdigest() != WORKER_SHA256:
        raise ValueError("worker_source_changed")
    nodes = [n for n in ast.parse(worker_bytes).body
             if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
    if {n.name for n in nodes} != FUNCTIONS:
        raise ValueError("worker_parser_missing")
    env = {"re": re, "RuleChangeError": ValueError,
           "SURICATA_ET_OVERRIDES": frozenset((2034802, 2034806)),
           "SURICATA_LLM_BIT": b"groot_llm_api",
           "SURICATA_LLM_MARKER_PROFILES": (
               (b"211.170.162.110", b"1"),
               (b"[211.170.162.110,211.170.162.111]", b"2"))}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "approved-parser", "exec"), env)
    return env


def active_map(data, env, duplicates_allowed):
    if not data or len(data) > 64 * 1024 * 1024 or b"\0" in data or b"\r" in data:
        raise ValueError("rule_bytes_invalid")
    data.decode("utf-8", "strict")
    result, duplicates = {}, []
    for line in env["_suricata_lines"](data):
        rule = env["_suricata_rule"](*line)
        sid, _ = env["_suricata_number"](rule, b"sid")
        rev, _ = env["_suricata_number"](rule, b"rev")
        gids = [v for k, v, *_ in rule["options"] if k == b"gid"]
        if len(gids) > 1 or (gids and not re.fullmatch(rb"[0-9]+", gids[0])):
            raise ValueError("gid_invalid")
        gid = int(gids[0]) if gids else 1
        if not 0 < sid < 2**32 or not 0 < rev < 2**32 or not 0 < gid < 2**32:
            raise ValueError("rule_number_invalid")
        # Header whitespace and whitespace around complete option tokens are
        # syntax. Option order and each value, including quoted bytes, stay exact.
        body = (tuple(rule["header"]), tuple((k, v) for k, v, *_ in rule["options"]))
        key = (gid, sid)
        if key in result:
            if not duplicates_allowed or gid != 1 or sid not in (2034802, 2034806):
                raise ValueError("unexpected_duplicate_sid")
            if rev == result[key][0]:
                raise ValueError("ambiguous_equal_revision")
            duplicates.append(sid)
        if key not in result or rev > result[key][0]:
            result[key] = (rev, body)
    if not result:
        raise ValueError("no_active_rules")
    return result, sorted(duplicates)


def compare(et, local, combined, generated, worker_bytes, native_module=None):
    if combined != et + local:
        raise ValueError("existing_concat_contract_broken")
    env = parser(worker_bytes)
    env["_validate_suricata_overrides"](local, et)
    local_map, _ = active_map(local, env, False)
    if not all((1, sid) in local_map for sid in (1000000, 2034802, 2034806)):
        raise ValueError("approved_exception_missing")
    mapper, context = (native_active_map, native_module) if native_module else (active_map, env)
    old, duplicates = mapper(combined, context, True)
    if duplicates != [2034802, 2034806]:
        raise ValueError("override_pair_not_exact")
    new, _ = mapper(generated, context, False)
    added, removed = sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys())
    changed = sorted(k for k in old.keys() & new.keys() if old[k] != new[k])
    # Metadata only: never export vendor rule bodies in summaries.
    return {"active_rule_maps_equal": not (added or removed or changed),
            "input_effective_rules": len(old), "output_active_rules": len(new),
            "approved_duplicate_sids": duplicates,
            "added_count": len(added), "removed_count": len(removed),
            "changed_count": len(changed),
            "added_ids_first_20": added[:20], "removed_ids_first_20": removed[:20],
            "changed_ids_first_20": changed[:20],
            "byte_concat_equal": generated == combined,
            "local_overrides_verified": True,
            "full_rules_parser": "installed_suricata_update_1.3.8" if native_module else "local_fixture_only"}
