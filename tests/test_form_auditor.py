import unittest
from modules.form_auditor import FormAuditor


class TestFormAuditor(unittest.TestCase):

    def setUp(self):
        self.config = {
            'forms': {
                'csrf_field_names': ['_token', 'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token'],
                'sensitive_keywords': ['password', 'secret', 'api_key', 'credit', 'ssn'],
            }
        }

    def test_no_forms(self):
        auditor = FormAuditor(self.config)
        html = '<html><body>No forms here</body></html>'
        results = auditor.run(html)
        self.assertEqual(len(results), 0)

    def test_form_with_csrf(self):
        auditor = FormAuditor(self.config)
        html = '''
        <html><body>
        <form action="/submit" method="POST">
            <input type="hidden" name="_token" value="abc123">
            <input type="text" name="username">
            <input type="submit">
        </form>
        </body></html>
        '''
        results = auditor.run(html)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['form_index'], 0)
        self.assertEqual(results[0]['action'], '/submit')
        self.assertEqual(results[0]['method'], 'POST')
        self.assertTrue(results[0]['csrf_protection']['present'])
        self.assertEqual(results[0]['csrf_protection']['field_name'], '_token')

    def test_form_without_csrf_post(self):
        auditor = FormAuditor(self.config)
        html = '''
        <html><body>
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit">
        </form>
        </body></html>
        '''
        results = auditor.run(html)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]['csrf_protection']['present'])
        self.assertIn('missing_csrf_token', results[0]['issues'])
        self.assertEqual(results[0]['risk_level'], 'HIGH')

    def test_form_get_no_csrf(self):
        auditor = FormAuditor(self.config)
        html = '''
        <html><body>
        <form action="/search" method="GET">
            <input type="text" name="q">
            <input type="submit">
        </form>
        </body></html>
        '''
        results = auditor.run(html)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]['csrf_protection']['present'])
        self.assertNotIn('missing_csrf_token', results[0]['issues'])
        self.assertEqual(results[0]['risk_level'], 'MEDIUM')

    def test_multiple_forms(self):
        auditor = FormAuditor(self.config)
        html = '''
        <html><body>
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="xyz">
            <input type="submit">
        </form>
        <form action="/register" method="POST">
            <input type="text" name="email">
            <input type="submit">
        </form>
        </body></html>
        '''
        results = auditor.run(html)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]['csrf_protection']['present'])
        self.assertEqual(results[0]['risk_level'], 'LOW')
        self.assertFalse(results[1]['csrf_protection']['present'])
        self.assertEqual(results[1]['risk_level'], 'HIGH')

    def test_empty_html(self):
        auditor = FormAuditor(self.config)
        results = auditor.run('')
        self.assertEqual(results, [])

    def test_none_html(self):
        auditor = FormAuditor(self.config)
        results = auditor.run(None)
        self.assertEqual(results, [])

    def test_sensitive_data_exposure(self):
        auditor = FormAuditor(self.config)
        html = '''
        <html><body>
        <form action="/process" method="POST">
            <input type="hidden" name="csrf_token" value="xyz">
            <input type="hidden" name="password" value="supersecret">
            <input type="submit">
        </form>
        </body></html>
        '''
        results = auditor.run(html)
        self.assertEqual(len(results), 1)
        self.assertIn('exposed_sensitive_data', results[0]['issues'])
        self.assertEqual(results[0]['risk_level'], 'HIGH')


if __name__ == '__main__':
    unittest.main()
