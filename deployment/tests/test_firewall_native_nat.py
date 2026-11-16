"""Management-source changes preserve native Docker/NAT ownership and order."""
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).parents[1] / 'firewall_native_nat.py'
s = importlib.util.spec_from_file_location('tested_native_management_nat', SOURCE)
n = importlib.util.module_from_spec(s); s.loader.exec_module(n)


def tagged(row):
    return row[row.index('--comment')+1] if '--comment' in row else ''


def tables(config):
    rows = [['-P','PREROUTING','ACCEPT'], ['-P','POSTROUTING','ACCEPT'], ['-N','DOCKER'],
            ['-A','PREROUTING','-m','addrtype','--dst-type','LOCAL','-j','DOCKER']]
    rows += [r for r in n.specs(config) if r[1] == 'PREROUTING']
    rows += [['-A','PREROUTING','-s','192.0.2.90/32','-j','RETURN'],
             ['-A','POSTROUTING','-s','172.18.0.0/16','-j','MASQUERADE']]
    rows += [r for r in n.specs(config) if r[1] == 'POSTROUTING']
    return rows


def execute(rows, commands):
    """Independent iptables -D/-I list semantics; never invoke a real binary."""
    result = copy.deepcopy(rows)
    for command in commands:
        if command[0] == '-D':
            result.remove(['-A', *command[1:]])
        elif command[0] == '-I':
            chain, offset = command[1], int(command[2])-1
            indices = [i for i,r in enumerate(result) if r[:2] == ['-A', chain]]
            position = indices[offset] if offset < len(indices) else indices[-1]+1
            result.insert(position, ['-A', chain, *command[3:]])
        else:
            raise AssertionError('mutation_outside_fixed_delete_insert_scope')
    return result


def observed(config, rows=None):
    rows = tables(config) if rows is None else rows
    text = '\n'.join(shlex.join(r) for r in rows)+'\n'
    with patch.object(n, 'run', return_value=text):
        ipt = n.ipt_snapshot(config)
    native = {'nftables': [
        {'table': {'family':'inet','name':'capstone_fw','handle':1}},
        {'chain': {'family':'inet','table':'capstone_fw','name':'input','handle':2,'type':'filter','policy':'drop'}},
        {'set': {'family':'inet','table':'capstone_fw','name':'agent_block','handle':3,
                 'type':'ipv4_addr','flags':['timeout'],'elem':[{'elem':{'val':'192.0.2.50','expires':120000}}]}},
        {'table': {'family':'ip','name':'nat','handle':4}},
        {'chain': {'family':'ip','table':'nat','name':'PREROUTING','type':'nat','handle':5}},
        {'chain': {'family':'ip','table':'nat','name':'POSTROUTING','type':'nat','handle':6}},
        {'chain': {'family':'ip','table':'nat','name':'DOCKER','handle':7}}]}
    for r in rows:
        if r[0] != '-A': continue
        # Stable identities for untouched rules; only DNAT groups may change.
        h = int(hashlib.sha256(shlex.join(r).encode()).hexdigest()[:8],16)+100
        native['nftables'].append({'rule':{'family':'ip','table':'nat','chain':r[1],
            'handle':h,'expr':[{'xt_fixture_opaque':shlex.join(r)}]}})
    return native, ipt


class NativeNatTests(unittest.TestCase):
    def setUp(self):
        self.before = copy.deepcopy(n.DEFAULT)
        self.after = n.with_management_sources(self.before, ['192.168.16.231/32','198.51.100.0/24'])

    def test_actual_single_source_baseline_keeps_three_rule_contract(self):
        rows = n.specs(self.before)
        self.assertEqual(len(rows),3)
        self.assertEqual(rows[0], ['-A','PREROUTING','-i','ens192','-s','192.168.16.231/32',
            '-p','tcp','-m','tcp','--dport','10443','-m','comment','--comment','capstone-basic-nat-dnat-0',
            '-j','DNAT','--to-destination','10.200.10.10:443'])

    def test_multiple_sources_are_distinct_rules_and_not_a_widened_supernet(self):
        rows = n.specs(self.after)
        self.assertEqual(len(rows),4)
        self.assertEqual([r[r.index('-s')+1] for r in rows if r[1]=='PREROUTING'],
                         ['192.168.16.231/32','198.51.100.0/24'])

    def test_parser_refuses_bad_types_unknown_fields_empty_or_forbidden_sources(self):
        for values in ([], ['0.0.0.0/0'], ['192.0.2.21/24'], ['127.0.0.1/32'],
                       ['224.0.0.0/4'], ['192.0.2.1/32\n'], ['::1'], [True], ['0.1.0.0/16']):
            with self.subTest(values=values), self.assertRaises(ValueError):
                n.with_management_sources(self.before,values)
        with self.assertRaises(ValueError): n.checked({**self.before,'schema':True})
        with self.assertRaises(ValueError): n.checked({**self.after,'shell':'anything'})

    def test_normalized_duplicate_and_adjacent_sources_do_not_duplicate_rules(self):
        c = n.with_management_sources(self.before,['192.0.2.21/32','192.0.2.20/32','192.0.2.21/32'])
        self.assertEqual(n.management_sources(c),['192.0.2.20/31'])
        self.assertEqual(len(n.specs(c)),3)

    def test_source_change_cannot_alter_port_destination_interface_or_internal_network(self):
        for key,value in [('external_interface','ens193'),('internal_network','10.200.10.0/25'),
                          ('forwards',[{'external_port':10444,'address':'10.200.10.10','port':443}])]:
            c = {**self.after,key:value}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError,'source_only'):
                n.management_transaction(self.before,c,tables(self.before))

    def test_transaction_changes_only_dnat_and_preserves_docker_relative_order(self):
        original = tables(self.before); transaction = n.management_transaction(self.before,self.after,original)
        result = execute(original,transaction['commands'])
        self.assertEqual(result,tables(self.after))
        self.assertEqual(original,tables(self.before))
        self.assertTrue(all(r[0]in('-D','-I')and r[1]=='PREROUTING' for r in transaction['commands']))
        self.assertNotIn('--flush',transaction['restore_text'])

    def test_update_to_one_source_and_inverse_both_match_exact_expected_state(self):
        first = n.management_transaction(self.before,self.after,tables(self.before))
        multiple = execute(tables(self.before),first['commands'])
        back = n.management_transaction(self.after,self.before,multiple)
        self.assertEqual(execute(multiple,back['commands']),tables(self.before))

    def test_multiple_forward_groups_keep_their_indices_and_foreign_rule_positions(self):
        before = copy.deepcopy(self.before)
        before['forwards'].append({'external_port':10444,'address':'10.200.10.20','port':8443})
        after = n.with_management_sources(before,n.management_sources(self.after))
        rows = tables(before)
        t = n.management_transaction(before,after,rows)
        self.assertEqual(execute(rows,t['commands']),tables(after))

    def test_foreign_rule_interleaved_inside_an_owned_group_is_refused(self):
        rows = tables(self.after); rows.insert(5,['-A','PREROUTING','-s','192.0.2.90/32','-j','RETURN'])
        # Two management rules occupy positions 4 and 6 (zero-based row offsets).
        with self.assertRaisesRegex(ValueError,'group_not_contiguous'):
            n.management_transaction(self.after,self.before,rows)

    def test_missing_or_extra_owned_rule_cannot_be_adopted_as_current_policy(self):
        for mutation in ('missing','extra'):
            rows = tables(self.before)
            if mutation=='missing': rows.pop(4)
            else: rows.append(copy.deepcopy(n.specs(self.before)[0]))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError,'owned_basic_nat_drift'):
                n.management_transaction(self.before,self.after,rows)

    def test_same_sources_is_noop_even_v1_and_v2_registry_shapes_differ(self):
        same = n.with_management_sources(self.before,['192.168.16.231/32'])
        t = n.management_transaction(self.before,same,tables(self.before))
        self.assertFalse(t['changed']);self.assertEqual(t['commands'],[])

    def test_syntax_only_path_sends_no_mutating_command(self):
        source, ipt = observed(self.before)
        with patch.object(n,'management_lock',return_value=contextlib.nullcontext()), \
             patch.object(n,'native',side_effect=[source,source]), \
             patch.object(n,'ipt_snapshot',side_effect=[ipt,ipt]), patch.object(n,'run')as run:
            result = n.change_management_sources(self.before,self.after,dry_run=True)
        self.assertFalse(result['mutation_performed']);self.assertFalse(result['changed'])
        self.assertEqual(run.call_count,1);self.assertIn('--test',run.call_args.args[0])

    def test_native_primitive_verifies_foreign_policy_and_masquerade_handles(self):
        old, ipt = observed(self.before); new, final = observed(self.after)
        with patch.object(n,'management_lock',return_value=contextlib.nullcontext()), \
             patch.object(n,'native',side_effect=[old,old,new]), \
             patch.object(n,'ipt_snapshot',side_effect=[ipt,ipt,final]), patch.object(n,'run')as run:
            result = n.change_management_sources(self.before,self.after)
        self.assertTrue(result['mutation_performed']);self.assertTrue(result['masquerade_handles_preserved'])
        self.assertEqual(run.call_count,2)
        self.assertTrue(all(c.args[0][0]=='iptables-restore' for c in run.call_args_list))

    def test_concurrent_policy_change_refused_after_syntax_and_before_mutation(self):
        old, ipt = observed(self.before); changed = copy.deepcopy(old)
        changed['nftables'][1]['chain']['policy']='accept'
        with patch.object(n,'management_lock',return_value=contextlib.nullcontext()), \
             patch.object(n,'native',side_effect=[old,changed]), \
             patch.object(n,'ipt_snapshot',side_effect=[ipt,ipt]), patch.object(n,'run')as run:
            with self.assertRaisesRegex(ValueError,'concurrent_policy_change'):
                n.change_management_sources(self.before,self.after)
        self.assertEqual(run.call_count,1);self.assertIn('--test',run.call_args.args[0])

    def test_recreated_masquerade_rule_is_not_success(self):
        old, ipt = observed(self.before); changed, final = observed(self.after)
        row = next(r['rule']for r in changed['nftables']if r.get('rule',{}).get('chain')=='POSTROUTING'
                   and 'capstone-basic-nat-egress'in str(r))
        row['handle']+=1
        with patch.object(n,'management_lock',return_value=contextlib.nullcontext()), \
             patch.object(n,'native',side_effect=[old,old,changed]), \
             patch.object(n,'ipt_snapshot',side_effect=[ipt,ipt,final]), patch.object(n,'run'):
            with self.assertRaisesRegex(RuntimeError,'readback_failed'):
                n.change_management_sources(self.before,self.after)

    def test_legacy_nat_is_not_implicitly_migrated_by_management_update(self):
        old, ipt = observed(self.before); old['nftables']+=n.definitions(self.before,False)
        with patch.object(n,'management_lock',return_value=contextlib.nullcontext()), \
             patch.object(n,'native',return_value=old), patch.object(n,'ipt_snapshot',return_value=ipt), \
             patch.object(n,'run')as run:
            with self.assertRaisesRegex(ValueError,'requires_existing_basic_nat'):
                n.change_management_sources(self.before,self.after)
        run.assert_not_called()

    def test_unprivileged_lock_refuses_before_opening_a_path(self):
        with patch.object(n.os,'geteuid',return_value=10001), patch.object(n.os,'open')as opened:
            with self.assertRaisesRegex(ValueError,'root_required'):
                with n.management_lock(): pass
        opened.assert_not_called()

    def test_cli_repeat_sources_preserves_native_restore_output(self):
        q=subprocess.run([sys.executable,'-I','-B',str(SOURCE),'print',
                          '--management-source','192.168.16.231/32','--management-source','198.51.100.0/24'],
                         capture_output=True,text=True,timeout=10)
        self.assertEqual(q.returncode,0,q.stderr)
        result=json.loads(q.stdout)
        self.assertEqual(result['config']['management_sources'],n.management_sources(self.after))
        self.assertEqual(result['iptables_restore'].count('--to-destination'),2)


if __name__ == '__main__': unittest.main()
