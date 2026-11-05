import unittest
import harness as h

class FirewallIPView(unittest.TestCase):
    def test_temporary_ip_has_observed_remaining_time_and_reference(self):
        objects=[{'set':{'family':'inet','table':'capstone_fw','name':'agent_block','elem':[{'elem':{'val':'192.168.16.232','expires':599001,'comment':'contain:'+'a'*32+':1793876000'}}]}}]
        text='\n'.join(h.firewall_ip_overview(objects))
        for value in ('192.168.16.232','600초','a'*32):self.assertIn(value,text)

    def test_empty_temporary_set_is_not_all_traffic_allowed(self):
        text='\n'.join(h.firewall_ip_overview([{'set':{'family':'inet','table':'capstone_fw','name':'agent_block'}}]))
        self.assertIn('정책에 의한 거부와 구분',text);self.assertNotIn('모든 통신 허용',text)

    def test_exemption_scope_is_not_generic_allowlist(self):
        rows=[{'set':{'family':'inet','table':'capstone_fw','name':'never_block','elem':[{'prefix':{'addr':'10.200.10.0','len':24}}]}}]
        text='\n'.join(h.firewall_ip_overview(rows));self.assertIn('10.200.10.0/24',text);self.assertIn('일반 접속 허용 아님',text)

    def test_opaque_docker_extension_is_not_unconditional_block(self):
        rows=[{'rule':{'family':'ip','table':'filter','chain':'FORWARD','handle':7,'expr':[{'xt':{'name':'conntrack','type':'match'}},{'drop':None}]}}]
        text='\n'.join(h.firewall_ip_overview(rows));self.assertIn('확장 조건 미해석: conntrack',text);self.assertIn('전체 허용/차단으로 단정하지',text)

    def test_address_port_negation_and_chain_order_are_visible(self):
        rows=[{'rule':{'family':'inet','table':'capstone_fw','chain':'input','handle':5,'expr':[{'match':{'op':'!=','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'@mgmt_src'}},{'match':{'op':'==','left':{'payload':{'protocol':'tcp','field':'dport'}},'right':22}},{'drop':None}]}}]
        text='\n'.join(h.firewall_ip_overview(rows))
        for value in ('출발지 IP != @mgmt_src','목적지 포트 == 22','규칙 순서','차단(DROP)'):self.assertIn(value,text)

if __name__=='__main__':unittest.main()
