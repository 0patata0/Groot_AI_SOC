#!/usr/bin/env python3
"""Offline checks for the 100113 volumetric-flood Wazuh rule candidate.

Uses the rule-change executor's own validators so the candidate passes the same
gate the governed propose_rule_edit path applies before any approval card. No
network, Docker or server access.
"""
import hashlib
import json
import re
import unittest
import xml.etree.ElementTree as ET
from importlib.machinery import SourceFileLoader
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EXECUTOR = SourceFileLoader("flood_rule_executor", str(ROOT / "infra/mcp/rule_change_executor.py")).load_module()
REGRESSION = SourceFileLoader("flood_rule_regression", str(HERE / "flood_rule_regression.py")).load_module()
BASE = (HERE / "base-5301922c-local_rules.xml").read_text(encoding="utf-8")  # pre-apply live baseline
LIVE_SYNCED = (ROOT / "infra/groot-b/local_rules.xml").read_text(encoding="utf-8")  # = applied 2026-11-13 07:37
EDIT = json.loads((HERE / "edit.json").read_text(encoding="utf-8"))
RULE = (HERE / "candidate-100113.xml").read_text(encoding="utf-8")


def apply_edits(text, edits):
    for e in edits:
        assert text.count(e["old_text"]) == 1
        text = text.replace(e["old_text"], e["new_text"], 1)
    return text


class FloodRuleCandidateTests(unittest.TestCase):
    def setUp(self):
        self.candidate = apply_edits(BASE, EDIT["edits"])
        self.root = ET.fromstring("<root>" + self.candidate + "</root>")
        self.rules = {r.attrib["id"]: r for r in self.root.iter("rule")}

    def test_edit_is_bound_to_the_live_baseline_and_passes_executor_gates(self):
        self.assertEqual(EDIT["target"], "b:wazuh-local-rules")
        self.assertEqual(hashlib.sha256(BASE.encode()).hexdigest(), EDIT["base_sha256"])
        self.assertLessEqual(len(EDIT["reason"]), 200)
        EXECUTOR._validated_edits(EDIT["edits"])
        EXECUTOR._validate_candidate("wazuh", self.candidate)
        # inserted directly BEFORE the 100112 burst rule (see test_defined_between_parent_and_burst_rule)
        self.assertEqual(EDIT["edits"][0]["new_text"], RULE + EDIT["edits"][0]["old_text"])

    def test_only_rule_100113_is_added_and_existing_rules_are_unchanged(self):
        base_ids = [r.attrib["id"] for r in ET.fromstring("<root>" + BASE + "</root>").iter("rule")]
        cand_ids = [r.attrib["id"] for r in self.root.iter("rule")]
        self.assertNotIn("100113", base_ids)
        self.assertEqual(sorted(cand_ids), sorted(base_ids + ["100113"]))
        self.assertEqual(len(cand_ids), len(set(cand_ids)))
        self.assertEqual(self.candidate.replace(RULE, "", 1), BASE)

    def test_rule_shape_child_of_medium_level_and_labels(self):
        r = self.rules["100113"]
        self.assertGreaterEqual(int(r.attrib["level"]), 9)  # reaches the level>=9 controller
        self.assertEqual(r.findtext("if_sid"), "100111")
        field = r.find("field")
        self.assertEqual((field.attrib["name"], field.attrib.get("type")), ("alert.signature_id", "pcre2"))
        labels = r.findtext("group").strip(",").split(",")
        self.assertIn("capstone_ids_burst_candidate", labels)  # keeps 100112 burst counting unchanged
        self.assertIn("capstone_volumetric_flood", labels)
        self.assertEqual(r.find("mitre").findtext("id"), "T1498")

    def test_defined_between_parent_and_burst_rule(self):
        # Wazuh links an if_matched_group correlation rule only to group members loaded
        # before it. With 100113 after 100112 the isolated candidate engine stopped firing
        # the same-source 100112 burst for flood SIDs, so the order is a hard requirement.
        order = [x.attrib["id"] for x in self.root.iter("rule")]
        self.assertGreater(order.index("100113"), order.index("100111"))  # child after parent
        self.assertLess(order.index("100113"), order.index("100112"))  # burst rule sees 100113

    def test_signature_pattern_matches_only_the_two_flood_sids(self):
        pattern = re.compile(self.rules["100113"].find("field").text)
        for sid in ("1000090", "1000091"):
            self.assertTrue(pattern.search(sid), sid)
        for sid in ("1000092", "1000009", "10000900", "2034806", "100009", " 1000090"):
            self.assertFalse(pattern.search(sid), sid)

    def test_no_new_active_response_or_command_elements(self):
        for tag in ("active-response", "command", "options"):
            self.assertIsNone(self.rules["100113"].find(tag))

    def test_repo_baseline_equals_the_applied_candidate(self):
        # Applied through the admin card (proposal 29f4194c..., 2026-11-13 07:37 KST).
        self.assertEqual(LIVE_SYNCED, self.candidate)
        self.assertEqual(hashlib.sha256(LIVE_SYNCED.encode()).hexdigest(),
                         'efdbffafb4aa6a6c21e36239b15ce54d18cfce67131711dc4ca3739ea18299a7')

    def test_regression_cases_are_consistent(self):
        names = [c["name"] for c in REGRESSION.CASES]
        self.assertEqual(len(names), len(set(names)))
        for c in REGRESSION.CASES:
            for engine in ("before", "candidate"):
                self.assertIn(c[engine]["final"], (100110, 100111, 100112, 100113))
            for engine in ("before", "candidate"):
                ids = c[engine].get("ids")
                if ids:
                    self.assertEqual((len(ids), ids[-1]), (len(c["logs"]), c[engine]["final"]), c["name"])
                    self.assertEqual([i + 1 for i, v in enumerate(ids) if v == 100112], c[engine]["burst_at"])
        changed = [c["name"] for c in REGRESSION.CASES if c["before"]["final"] != c["candidate"]["final"]]
        self.assertEqual(sorted(changed), ["flood_icmp_single", "flood_syn_single",
                                           "two_sources_flood_no_per_source_burst"])
        # the per-source burst survives for flood-only and mixed same-source sequences
        for name in ("same_source_flood_burst_still_100112", "mixed_same_source_flood_and_other_burst"):
            case = next(c for c in REGRESSION.CASES if c["name"] == name)
            self.assertEqual(case["candidate"]["burst_at"], [8])


if __name__ == "__main__":
    unittest.main()
