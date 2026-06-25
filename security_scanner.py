import argparse
import sys
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

from utils.logger import Logger
from utils.helpers import validate_url, sanitize_url, load_config
from utils.exceptions import ScannerError, ConfigError, InvalidTargetError
from modules.header_inspector import HeaderInspector
from modules.form_auditor import FormAuditor
from modules.banner_logger import BannerLogger
from modules.report_generator import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description='Security Scanner - HTTP Header, Form, and Network Banner Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python security_scanner.py --url http://localhost:8002/\n'
            '  python security_scanner.py --url https://example.com --config config.json\n'
            '  python security_scanner.py --url http://localhost:8002/ --output report.json --log-level DEBUG\n'
        )
    )
    parser.add_argument(
        '-u', '--url',
        required=False,
        help='Target URL to scan (e.g., http://localhost:8002/). Can also be set via target_url in .env'
    )
    parser.add_argument(
        '-c', '--config',
        default='config/scanner_config.json',
        help='Path to configuration file (default: config/scanner_config.json)'
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Path for JSON report output'
    )
    parser.add_argument(
        '--html',
        default=None,
        help='Path for HTML report output'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level (default: INFO)'
    )
    parser.add_argument(
        '--no-headers',
        action='store_true',
        help='Skip HTTP header inspection'
    )
    parser.add_argument(
        '--no-forms',
        action='store_true',
        help='Skip form compliance audit'
    )
    parser.add_argument(
        '--no-banners',
        action='store_true',
        help='Skip network banner logging'
    )
    return parser.parse_args()


def setup_logging(level_name):
    level_map = {
        'DEBUG': 10,
        'INFO': 20,
        'WARNING': 30,
        'ERROR': 40,
    }
    level = level_map.get(level_name.upper(), 20)


def main():
    load_dotenv()
    args = parse_args()
    setup_logging(args.log_level)

    Logger.info('Security Scanner v1.0')

    raw_url = args.url or os.environ.get('target_url') or os.environ.get('TARGET_URL') or 'http://localhost:8002/'
    if not raw_url:
        Logger.critical('Target URL must be provided via --url argument or target_url in .env file.')
        sys.exit(1)

    url = sanitize_url(raw_url)
    if not validate_url(url):
        Logger.critical(f'Invalid target URL: {url}')
        sys.exit(1)

    config_path = args.config
    if not os.path.exists(config_path):
        Logger.warning(f'Config file not found at {config_path}, using defaults.')
        config = {
            'target': {'url': url, 'follow_redirects': True, 'max_redirects': 5, 'timeout': 10, 'verify_ssl': True},
            'headers': {'enabled': not args.no_headers, 'checks': [
                'X-Frame-Options', 'Content-Security-Policy', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Referrer-Policy', 'X-XSS-Protection'
            ]},
            'forms': {'enabled': not args.no_forms, 'csrf_field_names': [
                '_token', 'csrf_token', 'csrfmiddlewaretoken', 'authenticity_token'
            ]},
            'ports': {'enabled': not args.no_banners, 'timeout': 5, 'list': [
                80, 443, 8080, 8443, 3306, 5432, 6379, 22, 21
            ]},
            'output': {'json': args.output or 'report.json', 'html': args.html}
        }
    else:
        config = load_config(config_path)
        config['target']['url'] = url
        config['headers']['enabled'] = not args.no_headers
        config['forms']['enabled'] = not args.no_forms
        config['ports']['enabled'] = not args.no_banners

    report_gen = ReportGenerator(config)
    report_gen.start_scan()

    inspector = None
    try:
        if config.get('headers', {}).get('enabled', True):
            inspector = HeaderInspector(config)
            header_results = inspector.run()
            report_gen.add_scanner_result('headers', header_results)
        else:
            Logger.info('Skipping HTTP header inspection.')
    except ScannerError as e:
        Logger.critical(f'Header inspection failed: {e}')

    html_content = inspector.get_response_text() if inspector else None
    try:
        if config.get('forms', {}).get('enabled', True):
            auditor = FormAuditor(config)
            form_results = auditor.run(html_content)
            report_gen.add_scanner_result('forms', form_results)
        else:
            Logger.info('Skipping form compliance audit.')
    except ScannerError as e:
        Logger.critical(f'Form audit failed: {e}')

    try:
        if config.get('ports', {}).get('enabled', True):
            banner_logger = BannerLogger(config)
            banner_results = banner_logger.run()
            report_gen.add_scanner_result('banners', banner_results)
        else:
            Logger.info('Skipping network banner logging.')
    except ScannerError as e:
        Logger.critical(f'Banner logging failed: {e}')

    report_gen.end_scan()
    report_gen.generate_console_report()

    output_path = args.output
    if not output_path:
        default_json = config.get('output', {}).get('json')
        if default_json and default_json != 'report.json':
            output_path = default_json
        else:
            parsed = urlparse(url)
            safe_host = parsed.hostname.replace('.', '_') if parsed.hostname else 'unknown'
            output_path = f"{safe_host}_report.json"

    if output_path:
        report_gen.generate_json_report(output_path)

    html_path = args.html or config.get('output', {}).get('html')
    if html_path:
        report_gen.generate_html_report(html_path)

    Logger.safe('Scan completed successfully.')


if __name__ == '__main__':
    main()
