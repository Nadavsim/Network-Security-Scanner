"""Tests for logging_setup.setup_logging.

Each test uses a fresh, never-before-used logger name rather than the real "scanner"
name that production code and tests/conftest.py's NullHandler use. pytest's own logging
plugin attaches a capture handler to loggers it sees used, which can accumulate across
tests sharing one name and confuse setup_logging()'s "already configured" check - a
unique name per test sidesteps that entirely instead of fighting pytest's instrumentation
with manual handler save/restore.
"""
from __future__ import annotations

import logging
import uuid

from logging_setup import setup_logging


def _fresh_name() -> str:
    return f"test-scanner-{uuid.uuid4()}"


def test_setup_logging_returns_a_logger_with_the_given_name(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    name = _fresh_name()
    logger = setup_logging(name)
    try:
        assert logger.name == name
        assert logger.level == logging.INFO
    finally:
        for handler in logger.handlers:
            handler.close()


def test_setup_logging_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    name = _fresh_name()

    logger1 = setup_logging(name)
    handler_count = len(logger1.handlers)
    logger2 = setup_logging(name)

    try:
        assert logger2 is logger1
        assert len(logger2.handlers) == handler_count  # no duplicate handler attached
    finally:
        for handler in logger1.handlers:
            handler.close()


def test_setup_logging_creates_a_timestamped_log_file_with_messages(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    name = _fresh_name()

    logger = setup_logging(name)
    try:
        logger.info("hello from a test")
        for handler in logger.handlers:
            handler.flush()

        # logs/, not the project root directly - see LOG_DIR in logging_setup.py.
        matches = list(tmp_path.glob("logs/scan_*.log"))
        assert len(matches) == 1
        content = matches[0].read_text(encoding="utf-8")
        assert "hello from a test" in content
        assert "INFO" in content
    finally:
        for handler in logger.handlers:
            handler.close()


def test_setup_logging_creates_the_log_directory_if_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "logs").exists()
    name = _fresh_name()

    logger = setup_logging(name)
    try:
        assert (tmp_path / "logs").is_dir()
    finally:
        for handler in logger.handlers:
            handler.close()
