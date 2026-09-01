"""Tests for benchmark_scan.format_results_table - the one piece of the benchmark
harness that's pure/deterministic. The actual scan-and-time functions (run_sync,
run_async, run_scenario) need real sockets and real elapsed time, so - consistent
with tcp_scan/tcp_scan_async themselves not being unit-tested - they're exercised
by actually running the script (python benchmark_scan.py --quick), not pytest.
"""
from __future__ import annotations

from benchmark_scan import ScenarioResult, format_results_table


def test_format_results_table_includes_header_and_rows():
    results = [
        ScenarioResult("scenario A", "sync/threaded", 1.23, [79, 80], True),
        ScenarioResult("scenario A", "async", 2.34, [79], False),
    ]
    table = format_results_table(results)

    assert "Scenario" in table and "Impl" in table and "Correct" in table
    assert "scenario A" in table
    assert "sync/threaded" in table
    assert "async" in table
    assert "1.23" in table
    assert "2.34" in table


def test_format_results_table_marks_match_as_yes_and_mismatch_as_no():
    results = [
        ScenarioResult("s", "sync/threaded", 1.0, [1, 2], True),
        ScenarioResult("s", "async", 1.0, [1], False),
    ]
    table = format_results_table(results)
    lines = table.splitlines()

    sync_line = next(line for line in lines if "sync/threaded" in line)
    async_line = next(line for line in lines if line.strip().startswith("s") and "async" in line)

    assert "yes" in sync_line
    assert "NO" in async_line


def test_format_results_table_empty_results_still_has_header():
    table = format_results_table([])
    assert "Scenario" in table
    assert len(table.splitlines()) == 2  # header + separator, no data rows
