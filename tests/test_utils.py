import unittest
import tempfile
import json
import os
from utils.helpers import validate_url, sanitize_url, mask_sensitive, load_config, get_environment_info, now_iso


class TestHelpers(unittest.TestCase):

    def test_validate_url_valid(self):
        self.assertTrue(validate_url('http://localhost:8000'))
        self.assertTrue(validate_url('https://example.com'))
        self.assertTrue(validate_url('http://127.0.0.1'))

    def test_validate_url_invalid(self):
        self.assertFalse(validate_url(''))
        self.assertFalse(validate_url('not-a-url'))
        self.assertFalse(validate_url('ftp://example.com'))

    def test_sanitize_url_adds_scheme(self):
        result = sanitize_url('localhost:8000')
        self.assertEqual(result, 'http://localhost:8000')

    def test_sanitize_url_strips_trailing_slash(self):
        result = sanitize_url('http://localhost:8000/')
        self.assertEqual(result, 'http://localhost:8000')

    def test_mask_sensitive_header(self):
        self.assertEqual(mask_sensitive('Bearer tok123', 'authorization'), '***MASKED***')

    def test_mask_sensitive_value(self):
        masked = mask_sensitive('mysecretvalue')
        self.assertIn('****', masked)
        self.assertNotEqual(masked, 'mysecretvalue')

    def test_load_config_valid(self):
        config_data = {'key': 'value'}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            tmp_path = f.name
        try:
            result = load_config(tmp_path)
            self.assertEqual(result, config_data)
        finally:
            os.unlink(tmp_path)

    def test_load_config_not_found(self):
        from utils.exceptions import ConfigError
        with self.assertRaises(ConfigError):
            load_config('nonexistent.json')

    def test_get_environment_info(self):
        info = get_environment_info()
        self.assertIn('python_version', info)
        self.assertIn('os', info)
        self.assertIn('platform', info)

    def test_now_iso(self):
        result = now_iso()
        self.assertRegex(result, r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')


if __name__ == '__main__':
    unittest.main()
