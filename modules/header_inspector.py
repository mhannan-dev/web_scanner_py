import requests
from urllib.parse import urlparse
from utils.logger import Logger
from utils.helpers import retry, mask_sensitive
from utils.exceptions import ConnectionError, TimeoutError, InvalidTargetError


class HeaderInspector:
    HEADERS_TO_CHECK = [
        'X-Frame-Options',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'Referrer-Policy',
        'X-XSS-Protection',
    ]

    EXPECTED_VALUES = {
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'X-Content-Type-Options': ['nosniff'],
        'X-XSS-Protection': ['1; mode=block', '0'],
    }

    RECOMMENDATIONS = {
        'X-Frame-Options': 'Set to DENY or SAMEORIGIN to prevent clickjacking attacks.',
        'Content-Security-Policy': 'Implement a CSP to mitigate XSS and data injection attacks.',
        'X-Content-Type-Options': 'Set to nosniff to prevent MIME type sniffing.',
        'Strict-Transport-Security': 'Enable HSTS to enforce HTTPS connections.',
        'Referrer-Policy': 'Set a Referrer-Policy to control referrer information leakage.',
        'X-XSS-Protection': 'Deprecated. Use CSP instead. If set, use "1; mode=block".',
    }

    def __init__(self, config):
        self.config = config
        self.target_url = config['target']['url']
        self.follow_redirects = config['target'].get('follow_redirects', True)
        self.max_redirects = config['target'].get('max_redirects', 5)
        self.timeout = config['target'].get('timeout', 10)
        self.verify_ssl = config['target'].get('verify_ssl', True)
        self.session = requests.Session()
        self.session.max_redirects = self.max_redirects
        self.results = {}
        self._last_response = None

    def _build_recommendation(self, header_name, present, value=None):
        if present and value:
            expected = self.EXPECTED_VALUES.get(header_name, [])
            if expected and value not in expected:
                return f'Value "{value}" does not match expected: {", ".join(expected)}.'
        if not present:
            return self.RECOMMENDATIONS.get(header_name, f'Missing {header_name} header.')
        return 'Header is properly configured.'

    def _determine_status(self, header_name, present, value=None):
        if not present:
            return 'FAIL'
        expected = self.EXPECTED_VALUES.get(header_name, [])
        if expected and value not in expected:
            return 'WARNING'
        if header_name == 'Strict-Transport-Security':
            parsed = urlparse(self.target_url)
            if parsed.scheme == 'https':
                return 'PASS' if present else 'FAIL'
            return 'WARNING' if not present else 'PASS'
        return 'PASS'

    @retry(max_attempts=2, delay=1, backoff=2, exceptions=(requests.RequestException,))
    def _make_request(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self._last_response = self.session.get(
            self.target_url,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=self.follow_redirects
        )
        return self._last_response

    def run(self):
        Logger.info(f'Starting HTTP Header Inspection on {self.target_url}')
        try:
            response = self._make_request()
            Logger.info(f'Received response with status {response.status_code}')
        except requests.exceptions.Timeout as e:
            Logger.critical(f'Request timed out: {e}')
            raise TimeoutError(f'Request to {self.target_url} timed out') from e
        except requests.exceptions.ConnectionError as e:
            Logger.critical(f'Connection failed: {e}')
            raise ConnectionError(f'Could not connect to {self.target_url}') from e
        except requests.exceptions.RequestException as e:
            Logger.critical(f'Request failed: {e}')
            raise ConnectionError(f'Request to {self.target_url} failed') from e

        enabled_checks = self.config.get('headers', {}).get('checks', self.HEADERS_TO_CHECK)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name in enabled_checks:
            header_lower = header_name.lower()
            present = header_lower in response_headers
            value = response_headers.get(header_lower) if present else None

            status = self._determine_status(header_name, present, value)
            recommendation = self._build_recommendation(header_name, present, value)

            result = {
                'present': present,
                'value': value if not present else mask_sensitive(value, header_name),
                'status': status,
                'recommendation': recommendation,
            }
            self.results[header_name] = result

            log_msg = f'{header_name}: {status}'
            if present:
                Logger.safe(log_msg)
            elif status == 'WARNING':
                Logger.warning(log_msg)
            else:
                Logger.critical(log_msg)

        return self.results

    def get_response_text(self):
        if self._last_response is not None:
            return self._last_response.text
        return None
