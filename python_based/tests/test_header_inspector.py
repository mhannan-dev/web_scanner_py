import unittest
from unittest.mock import patch, MagicMock
from modules.header_inspector import HeaderInspector


class TestHeaderInspector(unittest.TestCase):

    def setUp(self):
        self.config = {
            'target': {
                'url': 'http://localhost:8000',
                'follow_redirects': True,
                'max_redirects': 5,
                'timeout': 10,
                'verify_ssl': True,
            },
            'headers': {
                'checks': [
                    'X-Frame-Options',
                    'Content-Security-Policy',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security',
                    'Referrer-Policy',
                    'X-XSS-Protection',
                ]
            }
        }

    @patch('modules.header_inspector.requests.Session')
    def test_all_headers_present_correct(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'X-XSS-Protection': '1; mode=block',
        }
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_resp
        mock_session.return_value = mock_session_instance

        inspector = HeaderInspector(self.config)
        results = inspector.run()

        for header in self.config['headers']['checks']:
            self.assertIn(header, results)
            self.assertTrue(results[header]['present'])
            self.assertEqual(results[header]['status'], 'PASS')

    @patch('modules.header_inspector.requests.Session')
    def test_missing_headers(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_resp
        mock_session.return_value = mock_session_instance

        inspector = HeaderInspector(self.config)
        results = inspector.run()

        for header in self.config['headers']['checks']:
            self.assertIn(header, results)
            self.assertFalse(results[header]['present'])
            self.assertEqual(results[header]['status'], 'FAIL')

    @patch('modules.header_inspector.requests.Session')
    def test_wrong_value(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            'X-Frame-Options': 'ALLOWALL',
            'X-Content-Type-Options': 'sniff',
        }
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_resp
        mock_session.return_value = mock_session_instance

        inspector = HeaderInspector(self.config)
        results = inspector.run()

        self.assertTrue(results['X-Frame-Options']['present'])
        self.assertEqual(results['X-Frame-Options']['status'], 'WARNING')

        self.assertTrue(results['X-Content-Type-Options']['present'])
        self.assertEqual(results['X-Content-Type-Options']['status'], 'WARNING')

    @patch('modules.header_inspector.requests.Session')
    def test_get_response_text(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = '<html><body><form></form></body></html>'
        mock_session_instance = MagicMock()
        mock_session_instance.get.return_value = mock_resp
        mock_session.return_value = mock_session_instance

        inspector = HeaderInspector(self.config)
        inspector.run()
        self.assertEqual(inspector.get_response_text(), '<html><body><form></form></body></html>')


if __name__ == '__main__':
    unittest.main()
