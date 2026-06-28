class ScannerError(Exception):
    pass


class ConnectionError(ScannerError):
    pass


class TimeoutError(ScannerError):
    pass


class InvalidTargetError(ScannerError):
    pass


class ConfigError(ScannerError):
    pass


class RateLimitExceeded(ScannerError):
    pass
