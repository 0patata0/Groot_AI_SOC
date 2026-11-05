"""Workflow artifact integrity and no accidental authority/dispatch path."""
from pathlib import Path
import tempfile
import unittest
import workflow_contract as w

class WorkflowContract(unittest.TestCase):
    def test_every_project_skill_is_valid_and_selection_is_bounded(self):
        for name,marker in w.MARKERS.items():
            text=w.policy((name,))
            self.assertEqual(text.count(marker),1)
            self.assertNotIn('SOC_OUTPUT_CONTRACT_V1',text)
        self.assertEqual(w.policy(()),'')
        for names in (('unknown',),('../soc-query',),('soc-query','soc-query')):
            with self.assertRaises(ValueError):w.policy(names)

    def test_selected_procedures_do_not_load_unrelated_skills(self):
        text=w.policy(('soc-query',))
        self.assertIn(w.MARKERS['soc-query'],text)
        for name in ('soc-investigate','soc-change','soc-recover'):self.assertNotIn(w.MARKERS[name],text)

    def test_missing_and_symlink_skill_do_not_silently_proceed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'skills/soc-query';folder.mkdir(parents=True)
            with self.assertRaises(ValueError):w.policy(('soc-query',),directory)
            target=root/'outside';target.write_text('not a skill');(folder/'SKILL.md').symlink_to(target)
            with self.assertRaises(ValueError):w.policy(('soc-query',),directory)

    def test_wrong_identity_and_duplicate_marker_are_rejected(self):
        raw=(Path(w.__file__).parent/'skills/soc-query/SKILL.md').read_bytes()
        for invalid in (raw.replace(b'name: soc-query',b'name: soc-change'),raw+b'\nSOC_WORKFLOW_QUERY_V1'):
            with self.assertRaises(ValueError):w.policy_text('soc-query',invalid)

if __name__=='__main__':unittest.main()
