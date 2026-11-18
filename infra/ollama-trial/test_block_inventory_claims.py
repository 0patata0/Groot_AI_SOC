"""Current membership, quantities and feature configuration need distinct proof."""
import unittest
import harness as h
import test_evidence_report as f

MODE='block_inventory_does_not_verify_activation'
COUNT='block_inventory_membership_count_mismatch'


class BlockInventoryClaims(unittest.TestCase):
    def check(self,text,addresses):
        return h.action_claim_violations(f.Q,text,[f.call(f.BLOCK,{'blocks':addresses})])

    def test_current_list_members_generalize_without_becoming_service_state(self):
        for noun in ('주소','IP','아이피','대상','항목','구성원','원소','엔트리'):
            for addresses in ([],['192.0.2.232']):
                text='현재 임시 차단 목록의 활성화된 '+noun+'은 '+str(len(addresses))+'개입니다.'
                self.assertNotIn(MODE,self.check(text,addresses),text)
                self.assertNotIn(COUNT,self.check(text,addresses),text)
        text='임시 IP 차단 목록 조회 결과 빈 배열([])은 현재 활성화된 대상을 뜻하며 과거 차단 이력이나 기능 비활성을 의미하지 않는다.'
        self.assertNotIn(MODE,self.check(text,[]))
        for noun in ('대상 서버','대상 서비스','항목 설정','IP 차단 기능'):
            self.assertIn(MODE,self.check('임시 차단 목록의 활성화된 '+noun+'은 정상입니다.',[]))

    def test_actual_hermes_and_sdk_adjectives_describe_observed_addresses(self):
        for text in (
                '임시 차단 목록 조회 결과 빈 배열은 현재 활성화된 주소가 없음을 뜻합니다.',
                '임시 IP 차단 목록(list_blocks) 조회 결과 빈 목록으로, 현재 활성화된 임시 차단 주소는 없습니다.',
                '임시 IP 차단 목록이 반환0건으로 현재 활성화된 주소가 없음을 뜻합니다.',
                '현재 임시 IP 차단 목록의 활성화된 임시 IP 차단 주소는 0개입니다.',
                '현재 차단 목록의 active IP addresses: 0개입니다.'):
            self.assertNotIn(MODE,self.check(text,[]),text)
            self.assertNotIn(COUNT,self.check(text,[]),text)
        for text in ('현재 차단 목록의 활성화된 주소는 1개입니다.',
                     '현재 차단 목록의 활성화된 IP는 1개입니다.'):
            self.assertEqual(self.check(text,['192.0.2.232']),[],text)

    def test_observed_membership_does_not_attest_an_independent_feature_claim(self):
        for text in (
                '임시 차단 목록의 활성화된 주소가 없습니다. 차단 기능은 활성화되어 있습니다.',
                '임시 차단 목록은 0개이며 차단 기능이 비활성 상태입니다.',
                '임시 차단 목록의 활성화된 IP 차단 기능은 정상입니다.',
                '현재 차단 목록은 비어 있습니다. 자동 차단 기능은 꺼져 있습니다.'):
            self.assertIn(MODE,self.check(text,[]),text)

    def test_empty_and_nonempty_list_cannot_support_a_wrong_total_or_absence(self):
        for addresses in ([],['192.0.2.232']):
            actual=len(addresses)
            for amount in (0,1,2,10):
                text='현재 임시 차단 목록의 활성화된 주소는 '+str(amount)+'개입니다.'
                self.assertEqual(COUNT in self.check(text,addresses),amount!=actual,text)
        for text in ('현재 임시 차단 목록은 비어 있습니다.',
                     '임시 차단 목록 조회 결과 빈 배열은 현재 활성화된 주소가 없음을 뜻합니다.',
                     '현재 차단 목록의 주소는 없습니다.'):
            self.assertIn(COUNT,self.check(text,['192.0.2.232']),text)

    def test_latest_failed_invalid_or_unread_payload_does_not_attest_membership(self):
        good=f.call(f.BLOCK)
        bad=[f.call(f.BLOCK,{'error':'unavailable'},is_error=True),
             f.call(f.BLOCK,{'blocks':[],'partial':True}),
             f.call(f.BLOCK,{'blocks':['invalid']}),dict(good,result_sha256='0'*64),
             f.call(f.BLOCK,arguments={'unexpected':True})]
        text='임시 차단 목록 조회 결과 빈 배열은 현재 활성화된 주소가 없음을 뜻합니다.'
        for calls in ([],*([good,x] for x in bad)):
            self.assertIsNone(h.READ.block_list_state(h.evidence_reads(calls)))
            issues=h.action_claim_violations(f.Q,text,calls)
            self.assertIn(MODE,issues)
            self.assertIn('unobserved_block_list_claim',issues)

    def test_direct_negative_feature_state_still_needs_configuration_proof(self):
        for text in ('임시 차단 기능이 비활성은 아닙니다.',
                     '차단 기능은 비활성 상태가 아닙니다.',
                     '차단 기능이 활성화되지 않았습니다.',
                     '차단 기능이 활성화 안 되어 있습니다.'):
            self.assertIn(MODE,self.check(text,[]),text)

    def test_conditions_unknowns_and_negative_evidence_do_not_assert_feature_state(self):
        for text in ('차단 기능이 비활성인 경우 관리자 검토가 필요합니다.',
                     '차단 기능이 비활성이 아니라면 별도 확인해야 합니다.',
                     '임시 차단 기능 활성화는 판단할 수 없습니다.',
                     '임시 차단 기능 비활성을 의미하지 않습니다.',
                     '임시 차단 기능 비활성의 증거는 아닙니다.'):
            self.assertNotIn(MODE,self.check(text,[]),text)

    def test_other_subject_limits_history_individual_ip_and_hypothetical_counts_stay_separate(self):
        for text in ('현재 차단 목록의 조회 한도는 50개입니다.',
                     '과거 차단 목록에는 10개가 있었습니다.',
                     '현재 차단 목록은 1개이며 WAF 경보는 10건입니다.',
                     '현재 차단 목록에서 192.0.2.99는 없습니다.',
                     '현재 차단 목록이 0개라면 다른 증거를 확인해야 합니다.',
                     '현재 차단 목록이 빈 배열이면 다른 증거를 확인해야 합니다.'):
            self.assertNotIn(COUNT,self.check(text,['192.0.2.232']),text)


if __name__=='__main__':unittest.main()
