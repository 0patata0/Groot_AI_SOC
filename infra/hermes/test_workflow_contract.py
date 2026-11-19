"""Workflow artifact integrity and no accidental authority/dispatch path."""
from pathlib import Path
import tempfile
import unittest
import workflow_contract as w

class WorkflowContract(unittest.TestCase):
    def skill_file(self,name):
        root=Path(w.__file__).parent
        candidates=[p for p in (root/'skills'/name/'SKILL.md',root/('skill-'+name+'.md')) if p.is_file()]
        self.assertEqual(len(candidates),1)
        return candidates[0]

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

    def test_peer_review_section_is_loaded_only_by_its_phase(self):
        """2026-11-13: peer comparison principles moved from the worker into the
        shared skill; investigation/query prompts keep their body without it."""
        section=w.section_policy(('soc-investigate',),'peer-review')
        for phrase in ('검토자 자신의 요청 조건','filters_outside_question','반환 표본 0건','경보 수집·색인 정상',
                       '이견(disagree)은 상대가 실제로 주장한 명제의 반대가'):
            self.assertIn(phrase,section)
        for names in (('soc-investigate',),('soc-query','soc-investigate','soc-change')):
            body=w.policy(names)
            self.assertNotIn('## 교차 검토 대조',body);self.assertNotIn('filters_outside_question',body)
        self.assertIn('## 서비스 원인 조사',w.policy(('soc-investigate',)))
        self.assertNotIn('교차 검토 대조',w.section_policy(('soc-investigate',),'service-investigation'))
        self.assertIn('질문이 장비·경보 종류를 지정한 조사는',w.policy(('soc-investigate',)))
        with self.assertRaises(ValueError):w.section_policy(('soc-query',),'peer-review')

    def test_service_report_is_phase_scoped_and_keeps_failure_and_design_unknown(self):
        section=w.section_policy(('soc-investigate',),'service-report')
        self.assertIn('실패 자체가 확인되지 않았으면',section)
        self.assertIn('타이머/cron 설정',section)
        self.assertIn('초기 확인 구간',section)
        self.assertNotIn('## 서비스 조사 보고',w.policy(('soc-investigate',)))
        self.assertNotIn('## 서비스 조사 보고',w.section_policy(('soc-investigate',),'service-investigation'))
        with self.assertRaises(ValueError):w.section_policy(('soc-query',),'service-report')

    def test_canonical_install_skill_fits_the_unchanged_loader_limit(self):
        raw=self.skill_file('soc-investigate').read_bytes()
        self.assertLessEqual(len(raw),24576)
        self.assertIn('SOC_WORKFLOW_INVESTIGATE_V1',w.policy_text('soc-investigate',raw))

    def test_service_section_missing_or_duplicate_is_not_silently_omitted(self):
        raw=self.skill_file('soc-investigate').read_text()
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
        raw=self.skill_file('soc-query').read_bytes()
        for invalid in (raw.replace(b'name: soc-query',b'name: soc-change'),raw+b'\nSOC_WORKFLOW_QUERY_V1'):
            with self.assertRaises(ValueError):w.policy_text('soc-query',invalid)

if __name__=='__main__':unittest.main()
