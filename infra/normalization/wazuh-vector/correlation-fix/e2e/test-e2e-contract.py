#!/usr/bin/env python3
"""Local synthetic aggregate checks. Never imports/runs the operator entry point."""
import ast
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
PROJECT = HERE.parent.parent
source = (HERE / "e2e-burst.py").read_text()
tree = ast.parse(source)
query = next(ast.literal_eval(node.value) for node in tree.body
             if isinstance(node, ast.Assign) and any(
                 isinstance(target, ast.Name) and target.id == "AGGREGATE_FILTER"
                 for target in node.targets))
manifest = json.loads((HERE / "run-manifest.json").read_text())
assert manifest["contract"] == "canary-burst-20-v1"
assert len(manifest["runs"]) == len({r["run_id"] for r in manifest["runs"]}) == 20
for run in manifest["runs"]:
    for scenario, key in [("canary-repeat", "repeat_key"), ("canary-cross", "cross_key")]:
        assert run[key] == hashlib.sha256((run["run_id"] + ":" + scenario).encode()).hexdigest()

repeat = [json.loads(x) for x in (PROJECT / "fixtures/correlation/canary-repeat.jsonl").read_text().splitlines()]
cross = [json.loads(x) for x in (PROJECT / "fixtures/correlation/canary-cross.jsonl").read_text().splitlines()]
rows = []
for number, run in enumerate(manifest["runs"]):
    for original, rule_id, scenario, key in [
            (repeat[number % 5], "100293", "canary-repeat", "repeat_key"),
            (cross[1], "100294", "canary-cross", "cross_key")]:
        data = copy.deepcopy(original)
        data["capstone_validation"].update(run_id=run["run_id"], scenario=scenario)
        data["capstone_norm"]["correlation_key"] = run[key]
        rows.append({"rule": {"id": rule_id, "level": 3}, "agent": {"id": "001"},
                     "location": "/var/log/capstone-vector/canary/normalized.jsonl", "data": data})

jq = shutil.which("jq")
assert jq, "preinstalled jq required; do not install a package"
passed = 1


def check(candidate, expected):
    global passed
    result = subprocess.run([jq, "-ce", "-L", str(PROJECT / "history-replay-b"),
                             "--argjson", "manifest", json.dumps(manifest), query],
                            input=json.dumps(candidate).encode(), capture_output=True, timeout=10)
    assert (result.returncode == 0) == expected
    if expected:
        tuples = json.loads(result.stdout)
        assert len(tuples) == 40 and len({(x["run_id"], x["rule_id"]) for x in tuples}) == 40
    passed += 1


check(rows, True)
check(list(reversed(rows)), True)
check(rows[:-1], False)
check(rows + [rows[0]], False)
for path, value in [
        (("capstone_validation", "run_id"), manifest["runs"][1]["run_id"]),
        (("capstone_validation", "scenario"), "canary-historical"),
        (("capstone_validation", "scenario"), "canary-repeat-duplicate"),
        (("capstone_norm", "correlation_key"), "f" * 64),
        (("capstone_norm", "source"), "nftables")]:
    modified = copy.deepcopy(rows)
    modified[0]["data"][path[0]][path[1]] = value
    check(modified, False)
print(json.dumps({"kind": "local_synthetic_e2e_aggregate_check", "passed": passed,
                  "source_ast_valid": True, "synthetic_runs": 20, "expected_tuples": 40,
                  "remote_connection": False, "operational_input": False,
                  "driver_runtime_validation": False}))
