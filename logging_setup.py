"""One-time setup for a persistent session log file, separate from console output.

Deliberately lightweight: this does NOT replace any existing print() calls (the
project's console UX stays exactly as-is). It just configures a single named logger
("scanner") with a file handler, so a handful of targeted logger.info()/warning()/
error() calls elsewhere can record key checkpoints - scans started/completed, ports
found, CVEs found, errors - as a persistent audit trail, independent of whatever
scrolled past in the terminal.

Log files go in a LOG_DIR ("logs/") subdirectory, created on demand, rather than
directly in the project root - a fresh scan_<timestamp>.log every session would
otherwise clutter the top-level file listing.

Any module can do `logger = logging.getLogger("scanner")` at module level and just use
it - Python's logging module hands back the same configured logger by name from
anywhere, so nothing needs to be passed around as a parameter. Before setup_logging()
runs, that logger has no handlers and effectively no-ops (default level is WARNING with
no handler attached), so calling network_scanner/service_detection functions directly in
tests never creates stray log files.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

LOGGER_NAME = "scanner"
LOG_DIR = "logs"


def setup_logging(name: str = LOGGER_NAME) -> logging.Logger:
    """Configures and returns the named logger (default "scanner"), writing to a
    timestamped file.

    Safe to call more than once for the same name (e.g. if ScannerApp were constructed
    twice in a session) - only attaches the file handler the first time. The name
    parameter exists mainly for tests: pytest's own logging plugin attaches its capture
    handler to loggers it sees used, which can accumulate across tests and confuse the
    "already configured" check below if every test shares the one real "scanner" name -
    passing a fresh, never-before-used name sidesteps that entirely.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOG_DIR, f"scan_{timestamp}.log")

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False  # don't also spam the root logger/console via any default handler

    return logger
