import json
import os
from datetime import datetime, timezone

from utils.logger import Logger
from utils.helpers import get_environment_info, now_iso


class ReportGenerator:
    def __init__(self, config):
        self.config = config
        self.start_time = None
        self.end_time = None
        self.scanner_results = {}

    def add_scanner_result(self, scanner_name, results):
        self.scanner_results[scanner_name] = results

    def _compute_summary(self):
        total_checks = 0
        passed = 0
        failed = 0
        warnings = 0

        headers = self.scanner_results.get('headers', {})
        if headers:
            for header_name, result in headers.items():
                total_checks += 1
                status = result.get('status', '')
                if status == 'PASS':
                    passed += 1
                elif status == 'FAIL':
                    failed += 1
                elif status == 'WARNING':
                    warnings += 1

        forms = self.scanner_results.get('forms', [])
        if forms:
            total_checks += len(forms)
            for form in forms:
                risk = form.get('risk_level', 'LOW')
                if risk == 'HIGH':
                    failed += 1
                elif risk == 'MEDIUM':
                    warnings += 1
                else:
                    passed += 1

        banners = self.scanner_results.get('banners', [])
        if banners is not None:
            total_checks += len(banners)

        return {
            'total_checks': total_checks,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
        }

    def _build_report(self):
        summary = self._compute_summary()
        duration = None
        if self.start_time and self.end_time:
            duration = round((self.end_time - self.start_time).total_seconds(), 2)

        report = {
            'scan_timestamp': now_iso(),
            'scan_duration_seconds': duration,
            'target': self.config.get('target', {}),
            'environment': get_environment_info(),
            'summary': summary,
            'results': {},
        }

        if self.scanner_results.get('headers'):
            report['results']['headers'] = self.scanner_results['headers']
        if self.scanner_results.get('forms'):
            report['results']['forms'] = self.scanner_results['forms']
        if self.scanner_results.get('banners'):
            report['results']['banners'] = self.scanner_results['banners']

        return report

    def start_scan(self):
        self.start_time = datetime.now(timezone.utc)
        Logger.info('Scan started.')

    def end_scan(self):
        self.end_time = datetime.now(timezone.utc)

    def generate_console_report(self):
        report = self._build_report()
        summary = report['summary']
        duration = report['scan_duration_seconds']

        print('\n' + '=' * 60)
        print('  SECURITY SCANNER REPORT')
        print('=' * 60)
        print(f'  Target:         {report["target"].get("url", "N/A")}')
        print(f'  Timestamp:      {report["scan_timestamp"]}')
        print(f'  Duration:       {duration}s')
        print(f'  Python:         {report["environment"].get("python_version", "N/A")}')
        print(f'  OS:             {report["environment"].get("os", "N/A")}')
        print('-' * 60)
        print(f'  Total Checks:   {summary["total_checks"]}')
        print(f'  Passed:         {summary["passed"]}')
        print(f'  Failed:         {summary["failed"]}')
        print(f'  Warnings:       {summary["warnings"]}')
        print('=' * 60 + '\n')

    def generate_json_report(self, output_path):
        report = self._build_report()
        try:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            Logger.safe(f'JSON report saved to {output_path}')
        except OSError as e:
            Logger.critical(f'Failed to write JSON report: {e}')

    def generate_html_report(self, output_path):
        report = self._build_report()
        summary = report['summary']

        html_rows = ''
        headers = report['results'].get('headers', {})
        for hdr, info in headers.items():
            color = '#28a745' if info['status'] == 'PASS' else ('#ffc107' if info['status'] == 'WARNING' else '#dc3545')
            html_rows += (
                f'<tr><td>{hdr}</td>'
                f'<td>{info["present"]}</td>'
                f'<td style="color:{color}">{info["status"]}</td>'
                f'<td>{info["recommendation"]}</td></tr>'
            )

        form_rows = ''
        for form in report['results'].get('forms', []):
            color = '#28a745' if form['risk_level'] == 'LOW' else ('#ffc107' if form['risk_level'] == 'MEDIUM' else '#dc3545')
            form_rows += (
                f'<tr><td>{form["form_index"]}</td>'
                f'<td>{form["action"]}</td>'
                f'<td>{form["method"]}</td>'
                f'<td>{form["csrf_protection"]["present"]}</td>'
                f'<td style="color:{color}">{form["risk_level"]}</td>'
                f'<td>{", ".join(form["issues"]) if form["issues"] else "None"}</td></tr>'
            )

        banner_rows = ''
        for svc in report['results'].get('banners', []):
            banner_rows += (
                f'<tr><td>{svc["port"]}</td>'
                f'<td>{svc["state"]}</td>'
                f'<td>{svc["service"]}</td>'
                f'<td>{svc["protocol"]}</td></tr>'
            )

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scanner Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
.card {{ background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
h1, h2, h3 {{ color: #333; }}
.summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
.summary-item {{ flex: 1; text-align: center; padding: 20px; border-radius: 8px; color: #fff; }}
.summary-total {{ background: #007bff; }}
.summary-passed {{ background: #28a745; }}
.summary-failed {{ background: #dc3545; }}
.summary-warnings {{ background: #ffc107; color: #333; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f8f9fa; }}
tr:hover {{ background: #f1f1f1; }}
.meta {{ color: #666; font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
<h1>Security Scanner Report</h1>
<div class="meta">
<p>Target: {report['target'].get('url', 'N/A')} | Timestamp: {report['scan_timestamp']} | Duration: {report['scan_duration_seconds']}s</p>
</div>
<div class="summary">
<div class="summary-item summary-total"><h3>{summary['total_checks']}</h3><p>Total Checks</p></div>
<div class="summary-item summary-passed"><h3>{summary['passed']}</h3><p>Passed</p></div>
<div class="summary-item summary-failed"><h3>{summary['failed']}</h3><p>Failed</p></div>
<div class="summary-item summary-warnings"><h3>{summary['warnings']}</h3><p>Warnings</p></div>
</div>
<div class="card">
<h2>HTTP Headers</h2>
<table><thead><tr><th>Header</th><th>Present</th><th>Status</th><th>Recommendation</th></tr></thead><tbody>{html_rows}</tbody></table>
</div>
<div class="card">
<h2>Form Audit</h2>
<table><thead><tr><th>#</th><th>Action</th><th>Method</th><th>CSRF</th><th>Risk</th><th>Issues</th></tr></thead><tbody>{form_rows}</tbody></table>
</div>
<div class="card">
<h2>Network Banners</h2>
<table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Protocol</th></tr></thead><tbody>{banner_rows}</tbody></table>
</div>
</div>
</body>
</html>'''

        try:
            with open(output_path, 'w') as f:
                f.write(html)
            Logger.safe(f'HTML report saved to {output_path}')
        except OSError as e:
            Logger.critical(f'Failed to write HTML report: {e}')
