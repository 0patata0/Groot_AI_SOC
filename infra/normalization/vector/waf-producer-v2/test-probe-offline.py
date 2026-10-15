#!/usr/bin/env python3
"""Offline parser/oracle regressions only; no subprocess, network or native writer."""
import calendar
import datetime
import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).with_name('probe-native-a.py')
spec=importlib.util.spec_from_file_location('waf_v2_probe',path)
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
BINDING='a'*64
REQUEST='b'*32
ISO='2026-10-14T21:00:00+09:00'
EPOCH=calendar.timegm(datetime.datetime.fromisoformat(ISO).utctimetuple())
VALUE=f'v2:{BINDING}:{REQUEST}:{EPOCH}.123:{ISO}'
STAMP='Wed Oct 14 21:00:00 2026'

class Cases(unittest.TestCase):
    def test_exact_v2_context_and_length(self):
        row=probe.parsed_v2(VALUE,STAMP)
        self.assertEqual(row['unique_id_bytes'],141)
        self.assertEqual(row['iso_epoch_difference_ms'],123)
        self.assertEqual(row['audit_naive_difference_ms'],-123)
    def test_truncated_rejected(self):
        with self.assertRaises(probe.base.Refused):probe.parsed_v2(VALUE[:-1])
    def test_legacy_rejected(self):
        with self.assertRaises(probe.base.Refused):probe.parsed_v2(BINDING+'-'+REQUEST)
    def test_suffix_rejected(self):
        with self.assertRaises(probe.base.Refused):probe.parsed_v2(VALUE+'x')
    def test_epoch_iso_mismatch_rejected(self):
        with self.assertRaises(probe.base.Refused):probe.parsed_v2(VALUE.replace(f'{EPOCH}.123',f'{EPOCH+1}.123'))
    def test_naive_time_mismatch_rejected(self):
        with self.assertRaises(probe.base.Refused):probe.parsed_v2(VALUE,'Wed Oct 14 21:00:03 2026')
    def test_invalid_calendar_rejected(self):
        with self.assertRaises(ValueError):probe.parsed_v2(VALUE.replace('2026-10-14T','2026-13-14T'))
    def test_no_offset_rejected(self):
        with self.assertRaises(probe.base.Refused):probe.parsed_v2(VALUE.replace('+09:00',''))
    def test_same_binding_generations_do_not_share_expected_records(self):
        item=object.__new__(probe.V2Probe)
        first={'binding':BINDING,'expected':['1'*32]}
        wanted={'identity':BINDING+'-'+'1'*32,'raw_sha256':'c'*64}
        other={'identity':BINDING+'-'+'2'*32,'raw_sha256':'d'*64}
        item.raw_rows=lambda g,k:[wanted]
        item.observed=lambda lane:[wanted,other]
        self.assertTrue(item.reader_exact(first,lane='vector_audit',kind='audit'))
        item.observed=lambda lane:[wanted,wanted,other]
        self.assertFalse(item.reader_exact(first,lane='vector_audit',kind='audit'))

if __name__=='__main__':unittest.main()
