import importlib.util
import contextlib
import io
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('protected_hosts', Path(__file__).parents[1] / 'protected_hosts.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProtectionTests(unittest.TestCase):
    hosts = ['192.0.2.10', '192.0.2.20', '192.0.2.30']

    def test_servers_and_literal_llm_cannot_be_omitted(self):
        self.assertEqual(module.protection_set(self.hosts, 'http://192.0.2.40:11434/v1', '192.0.2.20'),
                         '192.0.2.10,192.0.2.20,192.0.2.30,192.0.2.40')

    def test_hostname_needs_explicit_other_address(self):
        for value in ('', '192.0.2.10'):
            with self.assertRaises(ValueError):
                module.protection_set(self.hosts, 'http://llm.example.org/v1', value)
        self.assertIn('192.0.2.40', module.protection_set(self.hosts, 'http://llm.example.org/v1', '192.0.2.40'))

    def test_invalid_extra_rejected(self):
        for value in ('0.0.0.0', '127.0.0.1', '224.0.0.1', '192.0.2.1/24', '192.0.2.01',
                      '192.0.2.1,', '192.0.2.1\n', 'x;id', '::1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.protection_set(self.hosts, 'http://192.0.2.40/v1', value)

    def test_infrastructure_limit_matches_pipeline(self):
        extra=','.join('198.51.100.'+str(i) for i in range(1,30))
        with self.assertRaises(ValueError):
            module.protection_set(self.hosts, 'http://192.0.2.40/v1', extra)

    def test_legacy_cli_output_and_fixed_error_are_preserved(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = module.cli([*self.hosts, 'http://192.0.2.40/v1', '192.0.2.70'])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), '192.0.2.10,192.0.2.20,192.0.2.30,192.0.2.40,192.0.2.70\n')
        self.assertEqual(err.getvalue(), '')
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = module.cli([*self.hosts, 'http://llm.example/v1', ''])
        self.assertEqual(code, 64)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(err.getvalue(), 'invalid protection set; use IPv4 literals (LLM hostname needs explicit addresses)\n')


class AdministratorRangeTests(unittest.TestCase):
    def test_empty_and_horizontal_whitespace_remain_optional(self):
        for value in ('', ' ', '\t  '):
            with self.subTest(value=value):
                self.assertEqual(module.admin_cidrs(value), '')
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(module.cli(['--admin-cidrs', '']), 0)
        self.assertEqual(out.getvalue(), '\n')
        self.assertEqual(err.getvalue(), '')

    def test_single_ip_and_host_bits_are_normalized(self):
        cases = {'192.0.2.23': '192.0.2.23/32', ' 10.2.3.4/24 ': '10.2.3.0/24',
                 '192.168.15.91/24': '192.168.15.0/24', '172.16.1.2/12': '172.16.0.0/12',
                 '203.0.113.8/32': '203.0.113.8/32', '192.0.2.3/31': '192.0.2.2/31'}
        for raw, expected in cases.items():
            with self.subTest(raw=raw): self.assertEqual(module.admin_cidrs(raw), expected)

    def test_duplicates_contained_ranges_and_adjacent_networks_collapse_stably(self):
        raw = '192.168.15.128/25, 10.2.3.4,192.168.15.6/25,10.2.3.4/32,192.168.15.8/32'
        expected = '10.2.3.4/32,192.168.15.0/24'
        self.assertEqual(module.admin_cidrs(raw), expected)
        self.assertEqual(module.admin_cidrs(','.join(reversed(raw.split(',')))), expected)
        self.assertEqual(module.admin_cidrs(expected), expected)
        self.assertEqual(module.admin_cidrs('192.0.2.0,192.0.2.1'), '192.0.2.0/31')

    def test_whole_range_overlap_with_forbidden_classes_is_rejected(self):
        for raw in ('0.0.0.0/0', '192.168.1.2/0', '0.0.0.0', '0.0.0.1/24',
                    '127.0.0.1', '127.255.255.255/32', '126.1.2.3/7',
                    '224.0.0.1', '239.255.255.255', '223.0.0.1/2',
                    '192.168.1.0/24,127.0.0.1'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): module.admin_cidrs(raw)

    def test_invalid_syntax_control_characters_and_ipv6_are_rejected(self):
        for raw in ('::1', '2001:db8::/32', '::ffff:192.0.2.1', 'example.org', 'https://192.0.2.1',
                    '192.0.2.01', '192.0.2.1:443', '192.0.2.1/33', '192.0.2.1/-1',
                    '192.0.2.1/255.255.255.0', '192.0.2.1//24', '999.1.1.1',
                    '192.0.2.1,', ',192.0.2.1', '192.0.2.1,,192.0.2.2',
                    '192.0.2.1\n', '\r', '\0', '192.0.2.1\x7f', '192.0.2.1;id'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): module.admin_cidrs(raw)

    def test_input_size_and_count_are_bounded(self):
        with self.assertRaises(ValueError): module.admin_cidrs(' ' * (module.ADMIN_INPUT_LIMIT + 1))
        with self.assertRaises(ValueError): module.admin_cidrs(','.join(['192.0.2.1'] * (module.ADMIN_ENTRY_LIMIT + 1)))
        self.assertEqual(module.admin_cidrs(','.join(['192.0.2.1'] * module.ADMIN_ENTRY_LIMIT)), '192.0.2.1/32')
        for raw in (None, [], 3, False):
            with self.subTest(raw=raw), self.assertRaises(ValueError): module.admin_cidrs(raw)

    def test_cli_returns_plain_canonical_text_and_never_echoes_bad_input(self):
        with self.assertRaises(ValueError) as invalid:
            module.admin_cidrs('999.1.1.1')
        self.assertNotIn('999.1.1.1', str(invalid.exception))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(module.cli(['--admin-cidrs', '192.0.2.9/24,10.2.3.4']), 0)
        self.assertEqual(out.getvalue(), '10.2.3.4/32,192.0.2.0/24\n')
        self.assertEqual(err.getvalue(), '')
        for args in (['--admin-cidrs'], ['--admin-cidrs', 'private-invalid-input'],
                     ['--admin-cidrs', '', 'unexpected']):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(module.cli(args), 64)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('private-invalid-input', err.getvalue())
            self.assertNotIn('unexpected', err.getvalue())


if __name__ == '__main__':
    unittest.main()
