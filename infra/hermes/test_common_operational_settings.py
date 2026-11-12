#!/usr/bin/env python3
"""Enforce the single-source consolidation of LLM operational settings (task #6).

Offline, stdlib only: reads repo files relative to this test, no network,
subprocess, model or server access. These invariants guard that SOC skills,
the common scripts and the system prompt stay single-sourced in infra/hermes/
and that every SOC skill keeps the shared operating contract. Byte-identical
live copies across surfaces are a separate concern (Harness2 cross-copy +
the task #5 approval cards); this only pins the repo source of truth.

See OPERATIONAL_SETTINGS.md for the source map and common principles.
"""

import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]  # infra/hermes -> repo root
SKILLS_DIR = HERE / "skills"
WORKFLOW_SKILLS = {"soc-query": "SOC_WORKFLOW_QUERY_V1", "soc-investigate": "SOC_WORKFLOW_INVESTIGATE_V1",
                   "soc-change": "SOC_WORKFLOW_CHANGE_V1", "soc-recover": "SOC_WORKFLOW_RECOVER_V1"}
ALL_SKILLS = {"soc-output", *WORKFLOW_SKILLS}
COMMON_SCRIPTS = ("chat_markdown.py", "output_contract.py", "workflow_contract.py")


def _frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None, None
    for end in range(1, len(lines)):
        if lines[end] == "---":
            return "\n".join(lines[:end + 1]), lines[1:end]
    return None, None


class CommonOperationalSettingsTests(unittest.TestCase):
    def test_single_skill_source_tree(self):
        self.assertEqual({p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}, ALL_SKILLS)
        for skill in ALL_SKILLS:
            self.assertTrue((SKILLS_DIR / skill / "SKILL.md").is_file(), skill)
        # The dest filename skill-soc-*.md exists only on the servers; a copy of
        # it in the repo would be a forked, non-common source.
        self.assertEqual(list((REPO / "infra").rglob("skill-soc-*.md")), [])

    def test_skill_frontmatter_matches_official_window_and_name(self):
        for skill in ALL_SKILLS:
            text = (SKILLS_DIR / skill / "SKILL.md").read_text(encoding="utf-8")
            block, body = _frontmatter(text)
            self.assertIsNotNone(block, skill)
            self.assertLessEqual(len(block), 600, skill)  # mirrors harness2 window
            fields = dict(re.match(r"([A-Za-z0-9_-]+):\s?(.*)", line).groups()
                          for line in body if re.match(r"([A-Za-z0-9_-]+):\s?(.*)", line))
            self.assertEqual(fields.get("name"), skill)
            self.assertTrue(fields.get("description"), skill)

    def test_every_workflow_skill_reuses_the_common_output_contract(self):
        output = (SKILLS_DIR / "soc-output" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("SOC_OUTPUT_CONTRACT_V1", output)
        for skill, marker in WORKFLOW_SKILLS.items():
            text = (SKILLS_DIR / skill / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn(marker, text, skill)
            self.assertIn("soc-output", text, skill)  # common output reuse, not a per-skill format

    def test_common_scripts_and_prompt_are_single_sourced_in_hermes(self):
        for name in (*COMMON_SCRIPTS, "SOUL.groot.md"):
            self.assertTrue((HERE / name).is_file(), name)
            # Exactly one copy under infra/ (no surface-forked duplicate).
            copies = [p for p in (REPO / "infra").rglob(name)]
            self.assertEqual(copies, [HERE / name], (name, copies))

    def test_surface_deployers_source_skills_and_prompt_from_hermes(self):
        ollama = (REPO / "deployment" / "ollama_trial.py").read_text(encoding="utf-8")
        for needle in ("hermes/skills/", "hermes/skills/soc-output/SKILL.md", "hermes/SOUL.groot.md"):
            self.assertIn(needle, ollama, needle)
        mgmt = (REPO / "deployment" / "soc_management.py").read_text(encoding="utf-8")
        for needle in ("skills/soc-query/SKILL.md", "skills/soc-output/SKILL.md", "SOUL.groot.md"):
            self.assertIn(needle, mgmt, needle)


if __name__ == "__main__":
    unittest.main()
