import unittest
import json
import os
import tempfile
from modules.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.config = {
            'target': {'url': 'http://localhost:8000'},
        }
        self.generator = ReportGenerator(self.config)

    def test_add_scanner_result(self):
        self.generator.add_scanner_result('headers', {'X-Frame-Options': {'present': True, 'status': 'PASS'}})
        self.assertIn('headers', self.generator.scanner_results)

    def test_summary_all_pass(self):
        self.generator.add_scanner_result('headers', {
            'X-Frame-Options': {'present': True, 'status': 'PASS'},
            'X-Content-Type-Options': {'present': True, 'status': 'PASS'},
        })
        summary = self.generator._compute_summary()
        self.assertEqual(summary['total_checks'], 2)
        self.assertEqual(summary['passed'], 2)
        self.assertEqual(summary['failed'], 0)
        self.assertEqual(summary['warnings'], 0)

    def test_summary_with_failures(self):
        self.generator.add_scanner_result('headers', {
            'X-Frame-Options': {'present': False, 'status': 'FAIL'},
            'Content-Security-Policy': {'present': True, 'status': 'PASS'},
        })
        summary = self.generator._compute_summary()
        self.assertEqual(summary['total_checks'], 2)
        self.assertEqual(summary['passed'], 1)
        self.assertEqual(summary['failed'], 1)

    def test_summary_with_warnings(self):
        self.generator.add_scanner_result('headers', {
            'X-Frame-Options': {'present': True, 'value': 'ALLOWALL', 'status': 'WARNING'},
        })
        summary = self.generator._compute_summary()
        self.assertEqual(summary['warnings'], 1)

    def test_json_report_output(self):
        self.generator.add_scanner_result('headers', {'Test-Header': {'present': True, 'status': 'PASS', 'recommendation': 'OK'}})
        self.generator.start_scan()
        self.generator.end_scan()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp_path = f.name

        try:
            self.generator.generate_json_report(tmp_path)
            with open(tmp_path, 'r') as f:
                report = json.load(f)
            self.assertIn('scan_timestamp', report)
            self.assertIn('summary', report)
            self.assertIn('results', report)
            self.assertIn('headers', report['results'])
        finally:
            os.unlink(tmp_path)

    def test_html_report_output(self):
        self.generator.add_scanner_result('headers', {'Test-Header': {'present': True, 'status': 'PASS', 'recommendation': 'OK'}})
        self.generator.add_scanner_result('forms', [{
            'form_index': 0, 'action': '/test', 'method': 'POST',
            'csrf_protection': {'present': True, 'field_name': '_token', 'field_type': 'hidden'},
            'issues': [], 'risk_level': 'LOW'
        }])
        self.generator.add_scanner_result('banners', [{'port': 80, 'state': 'OPEN', 'service': 'nginx', 'protocol': 'TCP'}])
        self.generator.start_scan()
        self.generator.end_scan()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            tmp_path = f.name

        try:
            self.generator.generate_html_report(tmp_path)
            with open(tmp_path, 'r') as f:
                content = f.read()
            self.assertIn('Security Scanner Report', content)
            self.assertIn('HTTP Headers', content)
            self.assertIn('Form Audit', content)
            self.assertIn('Network Banners', content)
        finally:
            os.unlink(tmp_path)


if __name__ == '__main__':
    unittest.main()
