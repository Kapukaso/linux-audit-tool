"""
Security-conscious logging system for the Linux Security Hardening Toolkit.
Author: Kartik Soni

Features:
- Redaction of sensitive strings (passwords, private keys, hashes, tokens)
- Terminal formatting with color support where applicable
- File-based audit trail logging
"""

import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

# Sensitive patterns that should never be written to logs
SENSITIVE_PATTERNS = [
    (re.compile(r'(password\s*[:=]\s*)([^\s,]+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret\s*[:=]\s*)([^\s,]+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[_-]?key\s*[:=]\s*)([^\s,]+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token\s*[:=]\s*)([^\s,]+)', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'), '[REDACTED PRIVATE KEY]'),
    (re.compile(r'\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}'), '[REDACTED HASH]'),  # SHA-512 crypt hash
    (re.compile(r'\$y\$[a-zA-Z0-9./]{8,}\$[a-zA-Z0-9./]{40,}'), '[REDACTED HASH]'),   # yescrypt hash
]


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs passwords and secret keys from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.sanitize(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = self._sanitize_dict(record.args)
            elif isinstance(record.args, tuple):
                cleaned = []
                for arg in record.args:
                    if isinstance(arg, dict):
                        cleaned.append(self._sanitize_dict(arg))
                    else:
                        cleaned.append(self.sanitize(str(arg)))
                record.args = tuple(cleaned)
        return True

    @classmethod
    def _sanitize_dict(cls, d: dict) -> dict:
        result = {}
        for k, v in d.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ["password", "secret", "token", "api_key", "apikey"]):
                result[k] = "[REDACTED]"
            else:
                result[k] = cls.sanitize(str(v))
        return result

    @staticmethod
    def sanitize(text: str) -> str:
        for pattern, replacement in SENSITIVE_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class AuditLogger:
    """Centralized logger management for secureaudit."""

    _logger: Optional[logging.Logger] = None

    @classmethod
    def setup_logger(
        cls,
        name: str = "secureaudit",
        log_file: Optional[str] = "logs/secureaudit.log",
        verbose: bool = False,
        quiet: bool = False
    ) -> logging.Logger:
        """Configures and returns the audit logger."""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        # Sensitive redaction filter
        redaction_filter = SensitiveDataFilter()
        logger.addFilter(redaction_filter)

        # Determine console log level
        if quiet:
            console_level = logging.WARNING
        elif verbose:
            console_level = logging.DEBUG
        else:
            console_level = logging.INFO

        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(console_level)
        console_format = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_format)
        console_handler.addFilter(redaction_filter)
        logger.addHandler(console_handler)

        # File Handler (if specified)
        if log_file:
            try:
                log_path = Path(log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_path, encoding="utf-8")
                file_handler.setLevel(logging.DEBUG)
                file_format = logging.Formatter(
                    fmt="%(asctime)s - %(name)s - [%(levelname)s] - [%(filename)s:%(lineno)d] - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
                file_handler.setFormatter(file_format)
                file_handler.addFilter(redaction_filter)
                logger.addHandler(file_handler)
            except (OSError, IOError) as e:
                logger.warning(f"Could not initialize file log handler at {log_file}: {e}")

        cls._logger = logger
        return logger

    @classmethod
    def get_logger(cls) -> logging.Logger:
        if cls._logger is None:
            return cls.setup_logger()
        return cls._logger
