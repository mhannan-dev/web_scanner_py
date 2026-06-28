import sys
from datetime import datetime


class Logger:
    COLORS = {
        "INFO": "\033[94m",
        "SAFE": "\033[92m",
        "WARNING": "\033[93m",
        "CRITICAL": "\033[91m",
        "RESET": "\033[0m",
    }
    LEVELS = {
        "INFO": "[*]",
        "SAFE": "[+]",
        "WARNING": "[!]",
        "CRITICAL": "[!!]",
    }

    @classmethod
    def _log(cls, level: str, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = cls.COLORS.get(level, cls.COLORS["RESET"])
        prefix = cls.LEVELS.get(level, "[*]")
        reset = cls.COLORS["RESET"]
        line = f"{color}{prefix} {timestamp} - {message}{reset}"
        if level in ("WARNING", "CRITICAL"):
            print(line, file=sys.stderr)
        else:
            print(line)

    @classmethod
    def info(cls, message: str) -> None:
        cls._log("INFO", message)

    @classmethod
    def safe(cls, message: str) -> None:
        cls._log("SAFE", message)

    @classmethod
    def warning(cls, message: str) -> None:
        cls._log("WARNING", message)

    @classmethod
    def critical(cls, message: str) -> None:
        cls._log("CRITICAL", message)
