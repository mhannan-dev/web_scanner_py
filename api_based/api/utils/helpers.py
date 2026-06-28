import time
import re
import json
import os
import sys
import platform
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from functools import wraps
from .exceptions import ConfigError, RateLimitExceeded


URL_REGEX = re.compile(
    r'^https?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?'
    r'|localhost'
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)

SENSITIVE_HEADERS = ['authorization', 'cookie', 'x-api-key', 'set-cookie']


def validate_url(url):
    if not url or not URL_REGEX.match(url):
        return False
    return True


def sanitize_url(url):
    url = url.strip()
    if '://' not in url:
        url = 'http://' + url
    return url.rstrip('/')


def mask_sensitive(value, header_name=None):
    if header_name and header_name.lower() in SENSITIVE_HEADERS:
        return '***MASKED***'
    if value and len(value) > 4:
        return value[:2] + '****' + value[-2:]
    return '***MASKED***'


def load_config(config_path):
    if not os.path.exists(config_path):
        raise ConfigError(f'Configuration file not found: {config_path}')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError as e:
        raise ConfigError(f'Invalid JSON in configuration file: {e}')


def get_environment_info():
    return {
        'python_version': sys.version.split()[0],
        'os': platform.system(),
        'os_version': platform.version(),
        'platform': platform.platform()
    }


def rate_limiter(max_per_second):
    min_interval = 1.0 / max_per_second

    def decorator(func):
        last_called = [0.0]

        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_called[0] = time.time()
            return ret

        return wrapper

    return decorator


def retry(max_attempts=3, delay=1, backoff=2, exceptions=(Exception,)):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts - 1:
                        raise
                    time.sleep(current_delay)
                    current_delay *= backoff
            return None
        return wrapper
    return decorator


def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
