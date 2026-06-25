import unittest
from unittest.mock import patch, MagicMock
from modules.header_inspector import HeaderInspector
from modules.form_auditor import FormAuditor
from modules.report_generator import ReportGenerator


class TestScannerIntegration(unittest.TestCase):

    @patch('modules.header_inspector.requests.Session')
    def test_header_form_integration(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
        }
        mock_resp.text = '''
        <html><body>
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="abc">
            <input type="text" name="user">
        </form>
        </body></html>
        '''
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_resp
        mock_session.return_value = mock_session_instance

        config = {
            'target': {'url': 'http://localhost:8000', 'follow_redirects': True, 'max_redirects': 5, 'timeout': 10, 'verify_ssl': True},
            'headers': {'checks': ['X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options']},
            'forms': {'csrf_field_names': ['_token', 'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token']},
        }

        inspector = HeaderInspector(config)
        header_results = inspector.run()
        self.assertIn('X-Frame-Options', header_results)

        html = inspector.get_response_text()
        auditor = FormAuditor(config)
        form_results = auditor.run(html)
        self.assertEqual(len(form_results), 1)
        self.assertTrue(form_results[0]['csrf_protection']['present'])

    def test_report_generator_summary(self):
        config = {'target': {'url': 'http://test.com'}}
        report = ReportGenerator(config)
        report.add_scanner_result('headers', {
            'X-Frame-Options': {'present': True, 'status': 'PASS', 'recommendation': 'OK'},
            'X-Content-Type-Options': {'present': False, 'status': 'FAIL', 'recommendation': 'Set nosniff'},
        })
        report.add_scanner_result('forms', [{
            'form_index': 0, 'action': '/test', 'method': 'POST',
            'csrf_protection': {'present': False, 'field_name': None, 'field_type': None},
            'issues': ['missing_csrf_token'], 'risk_level': 'HIGH'
        }])
        report.start_scan()
        report.end_scan()
        summary = report._compute_summary()
        self.assertEqual(summary['total_checks'], 3)
        self.assertEqual(summary['passed'], 1)
        self.assertEqual(summary['failed'], 2)


if __name__ == '__main__':
    unittest.main()
