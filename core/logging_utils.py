"""Logging setup shared by the CLI, orchestrator and modules."""

from __future__ import annotations

import logging
import os
import sys

_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"
_DATE_FORMAT = "%H:%M:%S"
_CONFIGURED = False


class _Formatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if sys.stderr.isatty() and not os.environ.get("NO_COLOR"):
            colors = {
                "DEBUG": "\033[90m",
                "INFO": "\033[36m",
                "WARNING": "\033[33m",
                "ERROR": "\033[31m",
                "CRITICAL": "\033[1;31m",
            }
            color = colors.get(record.levelname)
            if color:
                return f"{color}{message}\033[0m"
        return message


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    global _CONFIGURED
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    if _CONFIGURED:
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(_Formatter(_FORMAT, datefmt=_DATE_FORMAT))
    root.addHandler(handler)
    # Third-party HTTP libraries are chatty at DEBUG.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
