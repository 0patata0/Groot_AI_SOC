import gzip,hashlib,json,tempfile,unittest
from decimal import Decimal
from pathlib import Path
from inspect_hornet import decode,epoch_seconds,display_time,direction,auth_state,inspect


class HornetTests(unittest.TestCase):
    def test_duplicate_field_is_not_silently_replaced(self):
        with self.assertRaises(ValueError):decode('{"ts":1,"ts":2}')

    def test_nan_and_non_object_fail(self):
        for value in ['{"ts":NaN}','[]','{"ts":Infinity}']:
            with self.assertRaises(ValueError):decode(value)

    def test_epoch_is_exact_and_display_not_rounded(self):
        self.assertEqual(epoch_seconds(decode('{"ts":1714500846.980884}')['ts']),Decimal('1714500846.980884'))
        self.assertEqual(display_time(Decimal('1.0000001')),'1970-01-01T09:00:01.0000001+09:00')
        for value in [True,1.5,Decimal('1e-10000'),Decimal('NaN'),-1]:
            with self.assertRaises(ValueError):epoch_seconds(value)

    def row(self):return {'id.orig_h':'192.0.2.1','id.orig_p':123,'id.resp_h':'192.0.2.2','id.resp_p':22}

    def test_observer_is_not_automatically_destination(self):
        row=self.row()
        self.assertEqual(direction(row,{'192.0.2.1'}),'outbound')
        self.assertEqual(direction(row,{'192.0.2.2'}),'inbound')
        self.assertEqual(direction(row,{'198.51.100.1'}),'neither_endpoint_is_observer')

    def test_invalid_port_is_not_cast(self):
        for value in [True,'22',65536,-1]:
            with self.assertRaises(ValueError):direction({**self.row(),'id.resp_p':value},{'192.0.2.2'})

    def test_missing_authentication_is_not_false(self):
        self.assertEqual(auth_state({}),'missing')
        self.assertEqual(auth_state({'auth_success':False}),'false')
        with self.assertRaises(ValueError):auth_state({'auth_success':0})

    def run_fixture(self, root, changed_peer=False):
        records={'conn':{'ts':1,'uid':'u','proto':'tcp','conn_state':'S0',**self.row()},
                 'ssh':{'ts':1,'uid':'u',**self.row()},
                 'capture_loss':{'ts':2,'gaps':0,'acks':0,'percent_lost':0},
                 'stats':{'ts':2,'pkts_dropped':0},
                 'notice':{'ts':2,'note':'CaptureLoss::Too_Little_Traffic'}}
        if changed_peer:records['ssh']['id.orig_p']=124
        members=[]
        for kind,row in records.items():
            raw=(json.dumps(row)+'\n').encode();data=gzip.compress(raw);name=kind+'.log.gz';(root/name).write_bytes(data)
            members.append({'member':name,'local_name':name,'gzip_bytes':len(data),'gzip_sha256':hashlib.sha256(data).hexdigest(),'raw_bytes':len(raw),'raw_sha256':hashlib.sha256(raw).hexdigest(),'rows':1})
        return {'status':'complete','geo':0,'date_selected':'fixture','members':members}

    def test_missing_values_zero_estimate_notice_and_link_coexist(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m=self.run_fixture(root);r=inspect(m,root,['192.0.2.2'])
        self.assertEqual(r['missing_connection_fields']['duration'],1)
        self.assertEqual(r['ssh_auth_success_observations'],{'missing':1})
        self.assertEqual(r['ssh_connection_links'],{'unique_uid_tuple_match':1})
        self.assertEqual(r['notice_types'],{'CaptureLoss::Too_Little_Traffic':1})
        self.assertEqual(r['capture_loss_observations'],{'zero_reported':1})
        self.assertEqual(r['stats_drop_observations'],{'zero_reported':1})
        self.assertEqual(r['attack_verdicts_generated'],0)

    def test_uid_alone_does_not_prove_link(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m=self.run_fixture(root,True);r=inspect(m,root,['192.0.2.2'])
        self.assertEqual(r['ssh_connection_links'],{'ambiguous_or_endpoint_mismatch':1})

    def test_corrupted_source_and_repeated_member_fail(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);m=self.run_fixture(root);m['members'].append(m['members'][0])
            with self.assertRaises(ValueError):inspect(m,root,['192.0.2.2'])
            m['members'].pop();(root/'conn.log.gz').write_bytes(b'corrupt')
            with self.assertRaises(ValueError):inspect(m,root,['192.0.2.2'])

    def test_incomplete_acquisition_is_not_partial_success(self):
        with self.assertRaises(ValueError):inspect({'status':'running'},Path('.'),['192.0.2.2'])


if __name__=='__main__':unittest.main()
