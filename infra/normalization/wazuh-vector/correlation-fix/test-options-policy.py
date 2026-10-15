#!/usr/bin/env python3
"""Synthetic native-Ansible tests; use B's existing controller interpreter only.

Reads the production option-policy tasks verbatim. No Docker, service or
operational file commands are selected. No packages are installed.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml  # Already supplied by the pinned Ansible controller on B.


def main():
    base = Path(__file__).resolve().parent
    source = base / "apply-b.yml"
    play = yaml.safe_load(source.read_text())[0]
    names = [
        "Refuse ambiguous definitions or unsupported file framing",
        "Construct only the two reviewed option changes",
        "Require exact values and byte-equivalent unrelated lines",
    ]
    selected = [next(t for t in play["tasks"] if t["name"] == n) for n in names]
    if any(set(t) - {"name", "ansible.builtin.assert", "ansible.builtin.set_fact", "no_log"} for t in selected):
        raise SystemExit("Unexpected action in selected pure option policy")
    suffix = "analysisd.event_threads=1\nanalysisd.rule_matching_threads=1\n"
    cases = [
        ("append_both", "# Synthetic only\n", "# Synthetic only\n" + suffix),
        ("replace_both", "x.y=7\nanalysisd.event_threads=0\nanalysisd.rule_matching_threads=0\n", "x.y=7\n" + suffix),
        ("append_one", "analysisd.event_threads=1\nx.y=7\n", "analysisd.event_threads=1\nx.y=7\nanalysisd.rule_matching_threads=1\n"),
        ("whitespace_comment", "\tanalysisd.event_threads = 4 # old\nanalysisd.rule_matching_threads=4\n", suffix),
        ("idempotent", suffix, suffix),
        ("unrelated_utf8", "# 한글 원문\nx.y=2\n# analysisd.event_threads=9\n", "# 한글 원문\nx.y=2\n# analysisd.event_threads=9\n" + suffix),
        ("duplicate_event_reject", "analysisd.event_threads=0\nanalysisd.event_threads=1\n", None),
        ("duplicate_rule_reject", "analysisd.rule_matching_threads=0\nanalysisd.rule_matching_threads=1\n", None),
        ("no_final_lf_reject", "x.y=7", None),
        ("crlf_reject", "x.y=7\r\n", None),
        ("nul_reject", "x.y=\x007\n", None),
    ]
    results = []
    health_results = []
    with tempfile.TemporaryDirectory(prefix="capstone-option-policy-") as folder:
        root = Path(folder)
        for name in ("local-tmp", "remote-tmp"):
            (root / name).mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "PYTHONDONTWRITEBYTECODE": "1",
               "ANSIBLE_CONFIG": str(base.parent / "ansible.cfg"), "ANSIBLE_NOCOLOR": "1",
               "ANSIBLE_LOCAL_TEMP": str(root / "local-tmp"), "ANSIBLE_REMOTE_TEMP": str(root / "remote-tmp")}
        for name, original, expected in cases:
            tasks = list(selected)
            if expected is not None:
                tasks += [{"name": "Require independently specified exact expected bytes",
                           "ansible.builtin.assert": {"that": ["candidate_text == expected_text"]}, "no_log": True}]
            fixture = [{"name": name, "hosts": "localhost", "connection": "local", "gather_facts": False,
                        "vars": {"original_text": original, "expected_text": expected,
                                 "pin": {"options_sha256": hashlib.sha256(original.encode()).hexdigest()},
                                 "option_pattern": play["vars"]["option_pattern"]}, "tasks": tasks}]
            path = root / "fixture.json"
            path.write_text(json.dumps(fixture))
            r = subprocess.run(["/opt/capstone-automation/venv/bin/ansible-playbook", "-i", "localhost,", str(path)],
                               capture_output=True, env=env, timeout=45)
            passed = r.returncode == 0 if expected is not None else (
                r.returncode != 0 and names[0].encode() in r.stdout
                and names[1].encode() not in r.stdout
                and b"failed=1" in r.stdout
            )
            if not passed:
                print(json.dumps({"failed_case": name, "exit_code": r.returncode}))
                # Synthetic input only; useful diagnostics never include operational files.
                print(r.stdout.decode(errors="replace")[-6000:])
                print(r.stderr.decode(errors="replace")[-1000:])
                raise SystemExit(1)
            results.append({"case": name, "passed": True})
        mutation = next(t for t in play["tasks"] if t["name"] == "Apply two options and validate the same manager")
        running = "\n".join(f"{name} is running..." for name in
                            ("wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-logcollector"))
        health_cases = [
            ("all_running_zero", 0, running, True),
            ("all_running_disabled_optional", 1, running, True),
            ("missing_required", 1, running.replace("wazuh-logcollector is running...", ""), False),
            ("timeout_even_with_output", 124, running, False),
            ("required_not_running", 0, running.replace("wazuh-analysisd is running", "wazuh-analysisd is not running"), False),
        ]
        health_tasks = []
        for branch, task_name in (("block", "Wait for the required manager processes"), ("rescue", "Wait for recovery health")):
            policy = next(t for t in mutation[branch] if t["name"] == task_name)
            for name, rc, stdout, expected in health_cases:
                health_tasks.append({"name": f"{branch}_{name}", "ansible.builtin.assert":
                                     {"that": [f"({policy['until']}) == expected_health"]},
                                     "vars": {policy["register"]: {"rc": rc, "stdout": stdout}, "expected_health": expected}})
                health_results.append({"case": f"{branch}_{name}", "passed": True})
        fixture = [{"name": "Exact production health conditions", "hosts": "localhost", "connection": "local",
                    "gather_facts": False, "tasks": health_tasks}]
        path.write_text(json.dumps(fixture))
        r = subprocess.run(["/opt/capstone-automation/venv/bin/ansible-playbook", "-i", "localhost,", str(path)],
                           capture_output=True, env=env, timeout=45)
        if r.returncode:
            print(json.dumps({"failed_case": "health_conditions", "exit_code": r.returncode}))
            print(r.stdout.decode(errors="replace")[-6000:])
            raise SystemExit(1)
    print(json.dumps({"kind": "native_ansible_synthetic_option_policy", "passed": len(results),
                      "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "cases": results,
                      "health_conditions_passed": len(health_results), "health_cases": health_results,
                      "operational_options_written": False, "docker_or_service_called": False}))


if __name__ == "__main__":
    main()
