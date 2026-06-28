import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from utils.logger import Logger
from utils.exceptions import ScannerError


class FormAuditor:
    SENSITIVE_KEYWORDS = ['password', 'secret', 'api_key', 'token', 'credit', 'ssn']
    RISKY_HIDDEN_KEYWORDS = ['password', 'secret', 'credit', 'ssn', 'key']

    def __init__(self, config):
        self.config = config
        self.csrf_field_names = config.get('forms', {}).get(
            'csrf_field_names',
            ['_token', 'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token']
        )
        self.sensitive_keywords = config.get('forms', {}).get(
            'sensitive_keywords',
            self.SENSITIVE_KEYWORDS
        )
        self.results = []

    def _check_csrf_protection(self, form):
        for input_tag in form.find_all('input'):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name', '')
            if input_type == 'hidden' and input_name:
                name_lower = input_name.lower()
                if any(field_name in name_lower or name_lower == field_name for field_name in self.csrf_field_names):
                    return {
                        'present': True,
                        'field_name': input_name,
                        'field_type': input_type,
                    }
        return {'present': False, 'field_name': None, 'field_type': None}

    def _check_hidden_sensitive_data(self, form):
        issues = []
        for input_tag in form.find_all('input', type='hidden'):
            input_name = input_tag.get('name', '')
            input_value = input_tag.get('value', '')
            name_lower = input_name.lower()
            if any(kw in name_lower for kw in self.RISKY_HIDDEN_KEYWORDS):
                if input_value:
                    issues.append('exposed_sensitive_data')
                    Logger.warning(f'Hidden field "{input_name}" may expose sensitive data.')
        return issues

    def _validate_action(self, form):
        issues = []
        action = form.get('action', '')
        if not action or action.strip() == '':
            issues.append('missing_action')
            Logger.warning('Form has empty or missing action attribute.')
            return '/', issues
        action = action.strip()
        if action.startswith('javascript:'):
            issues.append('javascript_action')
            Logger.warning(f'Form action uses JavaScript: {action}')
        return action, issues

    def _validate_method(self, method, action):
        issues = []
        method_upper = method.upper() if method else 'GET'
        if method_upper not in ('GET', 'POST'):
            issues.append(f'unsupported_method_{method_upper}')
            Logger.warning(f'Form uses unusual method: {method_upper}')
        return method_upper, issues

    def _determine_risk_level(self, issues, csrf, method):
        if not csrf['present'] and method == 'POST':
            return 'HIGH'
        if 'exposed_sensitive_data' in issues:
            return 'HIGH'
        if not csrf['present']:
            return 'MEDIUM'
        if issues:
            return 'LOW'
        return 'LOW'

    def run(self, html_content):
        Logger.info('Starting Form Compliance Audit')
        if not html_content or not html_content.strip():
            Logger.warning('No HTML content provided for form audit.')
            return self.results

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception as e:
            Logger.critical(f'Failed to parse HTML: {e}')
            raise ScannerError(f'HTML parsing failed: {e}') from e

        forms = soup.find_all('form')
        Logger.info(f'Found {len(forms)} form(s) on the page.')

        for index, form in enumerate(forms):
            raw_method = form.get('method', 'GET')
            method, method_issues = self._validate_method(raw_method, form.get('action', ''))
            action, action_issues = self._validate_action(form)

            csrf = self._check_csrf_protection(form)
            sensitive_issues = self._check_hidden_sensitive_data(form)

            all_issues = list(set(method_issues + action_issues + sensitive_issues))

            if not csrf['present'] and method == 'POST':
                all_issues.append('missing_csrf_token')
                Logger.warning(f'Form {index} ({action}) uses POST without CSRF protection.')

            risk_level = self._determine_risk_level(all_issues, csrf, method)

            result = {
                'form_index': index,
                'action': action,
                'method': method,
                'csrf_protection': csrf,
                'issues': all_issues,
                'risk_level': risk_level,
            }
            self.results.append(result)

            if risk_level == 'HIGH':
                Logger.critical(f'Form {index} assessed as HIGH risk.')
            elif risk_level == 'MEDIUM':
                Logger.warning(f'Form {index} assessed as MEDIUM risk.')
            else:
                Logger.safe(f'Form {index} assessed as LOW risk.')

        return self.results
