"""Shared test fixtures/helpers."""
from __future__ import annotations

import logging

import pytest

from config import ScanConfig

# Prevents two things across the whole suite: (1) a stray scan_<timestamp>.log file if
# any test path ends up calling logging_setup.setup_logging() for real, and (2)
# "No handlers could be found"-style lastResort stderr noise from logger.info/warning/
# error calls sprinkled through network_scanner.py/service_detection.py/etc. when a test
# exercises those functions directly without ever going through ScannerApp.__init__.
logging.getLogger("scanner").addHandler(logging.NullHandler())


class FakeResponse:
    """Minimal stand-in for requests.Response, just enough for lookup_cves."""

    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def json(self) -> dict:
        return self._json_data


@pytest.fixture
def scan_config() -> ScanConfig:
    return ScanConfig()


@pytest.fixture
def make_response():
    """Factory fixture: make_response(200, {"vulnerabilities": [...]}) -> FakeResponse."""

    def _make(status_code: int, json_data: dict | None = None) -> FakeResponse:
        return FakeResponse(status_code, json_data)

    return _make
