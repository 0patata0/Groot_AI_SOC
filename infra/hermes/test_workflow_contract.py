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

    def test_service_section_reuses_skill_without_unrelated_event_procedures(self):
        text=w.section_policy(('soc-investigate',),'service-investigation')
        self.assertIn('journal_scope=all',text)
        self.assertIn('최근24시간',text)
        self.assertNotIn('DNS',text)
        self.assertIn(text.split('\n',2)[2],w.policy(('soc-investigate',)))
        with self.assertRaises(ValueError):w.section_policy(('soc-query',),'service-investigation')

    def test_service_section_missing_or_duplicate_is_not_silently_omitted(self):
        raw=(Path(w.__file__).parent/'skills/soc-investigate/SKILL.md').read_text()
        for value in (raw.replace('## 서비스 원인 조사','## 다른 절차'),raw+'\n## 서비스 원인 조사\n중복'):
            with tempfile.TemporaryDirectory() as directory:
                folder=Path(directory)/'skills/soc-investigate';folder.mkdir(parents=True)
                (folder/'SKILL.md').write_text(value)
                with self.assertRaises(ValueError):w.section_policy(('soc-investigate',),'service-investigation',directory)

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
