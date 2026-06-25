# COMPLETE SECURITY SCANNER PROMPT

## ROLE DEFINITION
You are a Senior DevOps Engineer and Code Quality Auditor with 10+ years of experience in Python development, security auditing, and infrastructure automation. Your expertise includes web application security, static code analysis, and deployment validation.

## CORE OBJECTIVE
Develop a production-grade Python security scanner that performs comprehensive local environment health checks, focusing on HTTP security posture, HTML structural compliance, and network fingerprinting.

## TECHNICAL SPECIFICATIONS

### Environment
- **Python Version**: 3.12.10
- **Core Libraries**: requests, beautifulsoup4, json
- **Additional Libraries** (if needed): socket, ssl, re, datetime, logging

### Architecture Requirements
- **Modular Design**: Separate modules for each scanner component
- **Clean Separation of Concerns**: Input handling, scanning logic, output formatting
- **Error Resilience**: Graceful handling of network timeouts, malformed responses, and missing elements
- **Configurable Logging**: DEBUG, INFO, WARNING, ERROR levels

## FUNCTIONAL REQUIREMENTS

### 1. HTTP HEADER INSPECTOR
**Purpose**: Audit HTTP response headers for security best practices

**Mandatory Headers to Check**:
- X-Frame-Options (should be: DENY or SAMEORIGIN)
- Content-Security-Policy (should exist with valid directives)
- X-Content-Type-Options (should be: nosniff)
- Strict-Transport-Security (if HTTPS)
- Referrer-Policy
- X-XSS-Protection (deprecated but check presence)

**Expected Behavior**:
- Make HEAD/GET request to target URL
- Parse response headers
- Generate pass/fail status for each header
- Provide recommendations for missing or misconfigured headers
- Handle redirects (follow maximum 5)

**Output Format**: Dictionary with header names as keys, each containing:
```json
{
  "header_name": {
    "present": true/false,
    "value": "actual_value_or_null",
    "status": "PASS/FAIL/WARNING",
    "recommendation": "specific_action_needed"
  }
}
```

### 2. FORM COMPLIANCE AUDITOR
**Purpose**: Analyze HTML forms for security token presence and structural integrity

**What to Scan**:
- All `<form>` elements in the HTML
- Check for CSRF protection mechanisms:
  - Hidden input fields named: _token, csrf_token, csrfmiddlewaretoken
  - Any input with name containing 'csrf' or 'token'
- Verify form action attributes (not empty, proper URL format)
- Validate form method (GET/POST appropriateness)
- Check for sensitive data exposure in hidden fields

**Expected Behavior**:
- Parse HTML with BeautifulSoup
- Iterate through all forms
- Analyze each form independently
- Log findings with severity levels

**Output Format**: List of form audit results:
```json
[
  {
    "form_index": 0,
    "action": "/submit",
    "method": "POST",
    "csrf_protection": {
      "present": true,
      "field_name": "_token",
      "field_type": "hidden"
    },
    "issues": ["missing_validation", "exposed_sensitive_data"],
    "risk_level": "LOW/MEDIUM/HIGH"
  }
]
```

### 3. NETWORK BANNER LOGGER
**Purpose**: Identify open ports and capture service banners for inventory

**What to Scan**:
- Common web ports: 80 (HTTP), 443 (HTTPS), 8080, 8443
- Application ports: 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis)
- Admin ports: 22 (SSH), 21 (FTP) - if accessible
- Default timeout: 5 seconds per port

**Expected Behavior**:
- Attempt TCP connection to each port
- Send appropriate probe if service-specific
- Capture first 1024 bytes of banner response
- Identify service type from banner
- Log service version if identifiable

**Output Format**: List of discovered services:
```json
[
  {
    "port": 443,
    "state": "OPEN",
    "service": "nginx/1.18.0",
    "banner": "220 FTP Server ready",
    "protocol": "TCP"
  }
]
```

## ADDITIONAL FEATURES

### Configuration Management
- Support for YAML/JSON configuration file
- Configurable: target URL, port list, header checks, log level
- Default config path: config/scanner_config.json

### Output Formats
- **Console**: Human-readable colored output
- **JSON**: Machine-parsable report
- **HTML**: Visual report (bonus feature)

### Reporting
- Summary statistics: total checks, passed, failed, warnings
- Timestamp of scan execution
- Scan duration
- Environment information (Python version, OS)

### Security Considerations
- Do not store or log sensitive information (passwords, tokens, API keys)
- Mask sensitive data in logs (e.g., Authorization headers)
- Handle SSL certificate validation (allow ignoring in config)
- Implement rate limiting to avoid server overload

## CODE QUALITY STANDARDS

### Documentation
- Google-style docstrings for all functions and classes
- README.md with installation and usage instructions
- Inline comments for complex logic

### Testing
- Provide unit tests for each component
- Include sample test URLs (use localhost or test environment)
- Mock external dependencies in tests

### Error Handling
- Custom exception classes
- Retry logic with exponential backoff
- Timeout management for all network calls
- Graceful degradation when services unavailable

## DELIVERABLE FORMAT

Provide a complete, runnable Python script with:

1. **Main Entry Point**: `if __name__ == "__main__":` with argparse support
2. **Configuration Loader**: JSON configuration file handler
3. **Three Scanner Classes**: HeaderInspector, FormAuditor, BannerLogger
4. **Report Generator**: Consolidates results from all scanners
5. **Utility Functions**: Logging, validation, helpers
6. **Example Configuration**: Full config file with all options

## USAGE EXAMPLE
```bash
python security_scanner.py --url http://localhost:8000 --config config.json --output report.json --log-level INFO
```

## SUCCESS CRITERIA
- Script runs without errors on Python 3.12.10
- All three scanners functional and return expected outputs
- Code follows PEP 8 styling
- Comprehensive error handling prevents crashes
- Output is clear, well-structured, and actionable
- Configuration is flexible and well-documented

## CONSTRAINTS
- DO NOT include exploit code, attack vectors, or penetration testing payloads
- DO NOT attempt to exploit or attack the target application
- ONLY perform passive scanning and information gathering
- ALL network connections should be non-intrusive
- Must handle local development environments safely (localhost, 127.0.0.1)

## DELIVERY INSTRUCTIONS
Provide the complete Python script with clear code sections, following all specifications above. Include comments explaining each major block and ensure the script is production-ready with proper error handling and logging.