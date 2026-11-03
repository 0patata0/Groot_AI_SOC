import copy
import unittest

from fw_policy_layout import layout,nat_merge_candidate


def fixture():
    rows=[{'table':{'family':'inet','name':'capstone_fw'}},
        {'chain':{'family':'inet','table':'capstone_fw','name':'input','type':'filter','hook':'input','prio':0,'policy':'drop'}}]
    for table,chain,hook,priority in [('capstone_gw','postrouting','postrouting',100),('capstone_fwd','prerouting','prerouting',-100),('capstone_fwd','postrouting','postrouting',100)]:
        if not any(o.get('table',{}).get('name')==table for o in rows):rows.append({'table':{'family':'ip','name':table}})
        rows.append({'chain':{'family':'ip','table':table,'name':chain,'type':'nat','hook':hook,'prio':priority,'policy':'accept'}})
        expr=[{'dnat':{'addr':'10.200.10.10','port':443}}] if hook=='prerouting' else [{'masquerade':None}]
        rows.append({'rule':{'family':'ip','table':table,'chain':chain,'handle':7,'expr':expr}})
    return {'nftables':rows}


class LayoutTests(unittest.TestCase):
    def test_every_rule_is_counted_once_and_zero_rule_drop_hook_is_not_unused(self):
        d=layout(fixture());self.assertEqual(d['groups'],{'NAT':3})
        self.assertTrue(all(r['hooks'] in (['PREROUTING'],['POSTROUTING']) for r in d['rules']))
        self.assertEqual(d['rule_count'],d['grouped_rule_count'])
        host=next(t for t in d['tables'] if t['table']=='capstone_fw')
        self.assertEqual(host['rules'],0);self.assertFalse(host['unused_proven'])
        self.assertTrue(any(c['policy']=='drop' for c in d['chains']))

    def test_jump_and_multi_hook_inheritance_never_double_counts_a_rule(self):
        data={'nftables':[{'table':{'family':'ip','name':'filter'}}]}
        for name,hook in [('input','input'),('forward','forward'),('shared',None)]:
            c={'family':'ip','table':'filter','name':name}
            if hook:c.update(hook=hook,type='filter',prio=0,policy='accept')
            data['nftables'].append({'chain':c})
            data['nftables'].append({'rule':{'family':'ip','table':'filter','chain':name,
                'expr':[{'jump':{'target':'shared'}}] if hook else [{'accept':None}]}})
        d=layout(data);self.assertEqual(d['rule_count'],3)
        r=next(r for r in d['rules'] if r['chain']=='shared')
        self.assertEqual(r['hooks'],['FORWARD','INPUT']);self.assertEqual(r['group'],'MULTI_HOOK')
        self.assertEqual(d['grouped_rule_count'],3)

    def test_packet_modification_is_classified_from_statement_not_table_name(self):
        data=fixture();data['nftables'].append({'rule':{'family':'inet','table':'capstone_fw','chain':'input',
            'expr':[{'mangle':{'key':{'meta':{'key':'mark'}},'value':1}}]}})
        self.assertEqual(layout(data)['groups']['MANGLE'],1)
        data['nftables'][-1]['rule']['expr']=[{'xt':{'type':'target','name':'MARK'}}]
        self.assertEqual(layout(data)['groups']['MANGLE'],1)


class CandidateTests(unittest.TestCase):
    def test_candidate_preserves_originals_and_limits_deletes_to_project_nat(self):
        d=fixture();before=copy.deepcopy(d);result=nat_merge_candidate(d)
        self.assertEqual(d,before);self.assertEqual(result['status'],'candidate_not_validated')
        commands=result['transaction']['nftables']
        self.assertEqual([c['delete']['table'] for c in commands if 'delete' in c],
            [{'family':'ip','name':'capstone_fwd'},{'family':'ip','name':'capstone_gw'}])
        rules=[c['add']['rule'] for c in commands if 'rule' in c.get('add',{})]
        self.assertEqual(len(rules),3)
        for r in rules:
            self.assertEqual(r['family'],'inet');self.assertEqual(r['table'],'capstone_fw')
            self.assertEqual(r['expr'][0]['match']['right'],'ipv4')
        self.assertEqual(next(x['dnat']['family'] for r in rules for x in r['expr'] if 'dnat' in x),'ip')

    def test_unknown_sets_extra_rules_or_changed_hook_refuse_a_candidate(self):
        for change in ('set','rule','priority','duplicate_chain'):
            data=fixture()
            if change=='set':data['nftables'].append({'set':{'family':'ip','table':'capstone_gw','name':'protected'}})
            if change=='rule':data['nftables'].append(copy.deepcopy(data['nftables'][-1]))
            if change=='priority':next(x['chain'] for x in data['nftables'] if x.get('chain',{}).get('table')=='capstone_gw')['prio']=99
            if change=='duplicate_chain':data['nftables'].append(copy.deepcopy(next(x for x in data['nftables'] if x.get('chain',{}).get('table')=='capstone_gw')))
            with self.assertRaises(ValueError):nat_merge_candidate(data)

    def test_existing_target_chains_refuse_replay(self):
        data=fixture();data['nftables'].append({'chain':{'family':'inet','table':'capstone_fw','name':'nat_prerouting'}})
        with self.assertRaisesRegex(ValueError,'already_exist'):nat_merge_candidate(data)


if __name__=='__main__':unittest.main()
