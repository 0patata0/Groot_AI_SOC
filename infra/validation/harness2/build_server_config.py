#!/usr/bin/env python3
"""Emit a credential-free fixed audit profile; never install or call a server."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


def build(layout):
    if layout not in ("legacy", "fresh"):
        raise ValueError("unknown_layout")
    root = Path(__file__).parent
    spec = importlib.util.spec_from_file_location("capstone_audit_builder", root / "server_audit.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        lock = json.loads((root / "framework.lock.json").read_text())
        origins = module.default_component_paths()
        home = "/opt/hermes-data" if layout == "legacy" else "/opt/capstone/siem/capstone-hermes"
        origins = {key: path.replace("/opt/hermes-data", home, 1) for key, path in origins.items()}
        return module.build_config(
            "/opt/capstone-harness2/vendor/" + module.PINNED_COMMIT,
            lock["files"],
            component_paths={key: "/var/lib/capstone-harness2/sources/" + key for key in origins},
            collector_facts={"layout": layout, "component_sources": origins,
                             "configuration_paths": ["/etc/capstone-ollama-trial/config.json",
                                 "/opt/capstone-ollama-trial/policy.py", home + "/config.yaml",
                                 home + "/management/config.yaml"]})
    finally:
        sys.modules.pop(spec.name, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", required=True, choices=("legacy", "fresh"))
    args = parser.parse_args()
    print(json.dumps(build(args.layout), ensure_ascii=True, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
