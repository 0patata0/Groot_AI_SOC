import unittest
from unittest.mock import patch
import test_runtime_health as existing

h=existing.h


class FailedUnits(unittest.TestCase):
    def test_unknown_unit_is_observable_without_raw_description(self):
        calls=[]
        def runner(argv, maximum, seconds):
            calls.append(argv)
            return 0,b'custom-new.service loaded failed failed SECRET_DESCRIPTION\n'
        row=h.systemd_failures(runner,existing.NOW)
        self.assertEqual(row['status'],'degraded')
        self.assertEqual(row['metrics']['failed_unit_0'],'custom-new.service')
        self.assertNotIn('SECRET',str(row))
        self.assertIn('--failed',calls[0]);self.assertNotIn('restart',str(calls))

    def test_zero_and_failed_query_are_distinct(self):
        row=h.systemd_failures(lambda *a:(0,b''),existing.NOW)
        self.assertEqual(row['metrics']['failed_units_total'],0)
        self.assertIn('zero_failed_units_is_not_all_services_healthy',row['limits'])
        for code,raw in ((1,b''),(0,b'bad row'),(0,b'u.service loaded active running description')):
            with self.assertRaises(ValueError):h.systemd_failures(lambda *a:(code,raw),existing.NOW)

    def test_bounded_results_preserve_total_and_do_not_hide_omission(self):
        raw='\n'.join(f'unit-{i}.service loaded failed failed description' for i in range(21)).encode()
        row=h.systemd_failures(lambda *a:(0,raw),existing.NOW)
        self.assertEqual(row['metrics']['failed_units_total'],21)
        self.assertEqual(row['metrics']['returned_units'],16)
        self.assertTrue(row['metrics']['unit_list_truncated'])
        self.assertIn('inspection_limit_reached',row['codes'])
        rows={t:h.observation('runtime',existing.NOW) for t in h.ROLE_TARGETS['security']}
        rows['a:systemd']=row
        self.assertEqual(h.validate(rows,'security',existing.NOW),rows)

    def test_duplicate_invalid_and_unbounded_units_are_rejected(self):
        for raw in (b'u.service loaded failed failed x\nu.service loaded failed failed y',
                    b'../../secret loaded failed failed x',
                    '\n'.join(f'u{i}.service loaded failed failed x' for i in range(513)).encode()):
            with self.assertRaises(ValueError):h.systemd_failures(lambda *a:(0,raw),existing.NOW)


if __name__=='__main__':unittest.main()
