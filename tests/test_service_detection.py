"""Tests for lookup_cves, sort_cves_by_severity, and _scan_single_port_with_nmap's
tcp_scan/nmap state cross-check. requests.get and time.sleep are always mocked, so no
test ever makes a real NVD call or actually waits out the rate-limit delay; nmap.PortScanner
is always a MagicMock, so no test ever shells out to a real nmap binary.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from service_detection import _scan_single_port_with_nmap, lookup_cves, sort_cves_by_severity


def test_lookup_cves_empty_product_short_circuits():
    cache = {}
    with patch("service_detection.requests.get") as mock_get:
        result = lookup_cves("", "1.0", cache)
    assert result == []
    mock_get.assert_not_called()


def test_lookup_cves_cache_hit_skips_network_and_sleep():
    cached = [{"id": "CVE-CACHED", "score": 9.8, "severity": "CRITICAL"}]
    cache = {("openssh", "8.2"): cached}
    with patch("service_detection.requests.get") as mock_get, \
         patch("service_detection.time.sleep") as mock_sleep:
        result = lookup_cves("OpenSSH", "8.2", cache)
    assert result == cached
    mock_get.assert_not_called()
    mock_sleep.assert_not_called()


def test_lookup_cves_cache_key_normalizes_case_and_whitespace():
    cached = [{"id": "CVE-CACHED", "score": 9.8, "severity": "CRITICAL"}]
    cache = {("openssh", "8.2"): cached}
    with patch("service_detection.requests.get") as mock_get:
        result = lookup_cves("  OpenSSH  ", " 8.2 ", cache)
    assert result == cached
    mock_get.assert_not_called()


def test_lookup_cves_success_extracts_id_score_and_severity_v31(make_response):
    cache = {}
    response = make_response(200, {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-1",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            }},
        ]
    })
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep") as mock_sleep:
        result = lookup_cves("OpenSSH", "8.2", cache)
    expected = [{"id": "CVE-2021-1", "score": 9.8, "severity": "CRITICAL"}]
    assert result == expected
    assert cache[("openssh", "8.2")] == expected
    mock_sleep.assert_called_once()


def test_lookup_cves_falls_back_to_v30_when_v31_absent(make_response):
    cache = {}
    response = make_response(200, {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2020-1",
                "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
            }},
        ]
    })
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep"):
        result = lookup_cves("Foo", "1.0", cache)
    assert result == [{"id": "CVE-2020-1", "score": 7.5, "severity": "HIGH"}]


def test_lookup_cves_falls_back_to_v2_with_top_level_severity(make_response):
    # CVSS v2 entries put baseSeverity as a SIBLING of cvssData, not inside it like v3 does.
    cache = {}
    response = make_response(200, {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2015-1",
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]},
            }},
        ]
    })
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep"):
        result = lookup_cves("Foo", "1.0", cache)
    assert result == [{"id": "CVE-2015-1", "score": 5.0, "severity": "MEDIUM"}]


def test_lookup_cves_prefers_v31_over_v30_and_v2_when_multiple_present(make_response):
    cache = {}
    response = make_response(200, {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-1",
                "metrics": {
                    "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
                    "cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                },
            }},
        ]
    })
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep"):
        result = lookup_cves("Foo", "1.0", cache)
    assert result == [{"id": "CVE-2021-1", "score": 9.8, "severity": "CRITICAL"}]


def test_lookup_cves_no_cvss_metrics_yields_none_score_and_severity(make_response):
    cache = {}
    response = make_response(200, {
        "vulnerabilities": [{"cve": {"id": "CVE-2024-99999", "metrics": {}}}]
    })
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep"):
        result = lookup_cves("Foo", "1.0", cache)
    assert result == [{"id": "CVE-2024-99999", "score": None, "severity": None}]


def test_lookup_cves_success_with_no_matches_still_caches_empty_list(make_response):
    cache = {}
    response = make_response(200, {"vulnerabilities": []})
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep"):
        result = lookup_cves("SomeProduct", "1.0", cache)
    assert result == []
    assert cache[("someproduct", "1.0")] == []


@pytest.mark.parametrize("status_code", [403, 429, 500])
def test_lookup_cves_error_statuses_return_empty_but_still_sleep(status_code, make_response):
    cache = {}
    response = make_response(status_code)
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep") as mock_sleep:
        result = lookup_cves("Foo", "1.0", cache)
    assert result == []
    mock_sleep.assert_called_once()  # a real network call still happened
    # A failed lookup must NOT be cached - caching it would permanently hide real CVEs
    # after a single transient rate-limit/error, since nothing would ever retry it.
    assert ("foo", "1.0") not in cache


def test_lookup_cves_request_exception_returns_empty_and_does_not_cache():
    cache = {}
    with patch("service_detection.requests.get",
               side_effect=requests.exceptions.ConnectionError("boom")), \
         patch("service_detection.time.sleep") as mock_sleep:
        result = lookup_cves("Foo", "1.0", cache)
    assert result == []
    assert ("foo", "1.0") not in cache
    mock_sleep.assert_called_once()


def test_lookup_cves_retries_after_a_failed_lookup_instead_of_using_stale_cache(make_response):
    # First call fails (403) and must not poison the cache; a second call for the same
    # product/version should make a real network request again, not serve a cached [].
    cache = {}
    fail_response = make_response(403)
    ok_response = make_response(200, {
        "vulnerabilities": [{"cve": {"id": "CVE-2021-1", "metrics": {}}}]
    })

    with patch("service_detection.requests.get", return_value=fail_response) as mock_get, \
         patch("service_detection.time.sleep"):
        first_result = lookup_cves("Foo", "1.0", cache)
    assert first_result == []
    assert ("foo", "1.0") not in cache
    mock_get.assert_called_once()

    with patch("service_detection.requests.get", return_value=ok_response) as mock_get, \
         patch("service_detection.time.sleep"):
        second_result = lookup_cves("Foo", "1.0", cache)
    mock_get.assert_called_once()  # proves this call hit the network, not a stale cache entry
    assert second_result == [{"id": "CVE-2021-1", "score": None, "severity": None}]
    assert cache[("foo", "1.0")] == second_result


def test_lookup_cves_malformed_response_shape_does_not_crash(make_response):
    cache = {}
    response = make_response(200, {"vulnerabilities": [{"cve": {}}, {"no_cve_key": True}]})
    with patch("service_detection.requests.get", return_value=response), \
         patch("service_detection.time.sleep"):
        result = lookup_cves("Foo", "1.0", cache)
    assert result == []


# ---------- sort_cves_by_severity ----------


def test_sort_cves_by_severity_orders_highest_score_first():
    cves = [
        {"id": "CVE-LOW", "score": 3.1, "severity": "LOW"},
        {"id": "CVE-CRITICAL", "score": 9.8, "severity": "CRITICAL"},
        {"id": "CVE-HIGH", "score": 7.5, "severity": "HIGH"},
    ]
    result = sort_cves_by_severity(cves)
    assert [c["id"] for c in result] == ["CVE-CRITICAL", "CVE-HIGH", "CVE-LOW"]


def test_sort_cves_by_severity_puts_unscored_last_not_first():
    cves = [
        {"id": "CVE-UNSCORED", "score": None, "severity": None},
        {"id": "CVE-LOW", "score": 2.0, "severity": "LOW"},
    ]
    result = sort_cves_by_severity(cves)
    assert [c["id"] for c in result] == ["CVE-LOW", "CVE-UNSCORED"]


def test_sort_cves_by_severity_empty_list():
    assert sort_cves_by_severity([]) == []


# ---------- _scan_single_port_with_nmap's tcp_scan/nmap state cross-check ----------


def test_scan_single_port_with_nmap_no_warning_when_state_matches_open(capsys):
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["10.0.0.1"]
    scanner.__getitem__.return_value = {"tcp": {80: {"state": "open", "name": "http"}}}

    result = _scan_single_port_with_nmap(scanner, "10.0.0.1", 80)

    assert result["state"] == "open"
    assert result["service"] == "http"
    assert "Warning" not in capsys.readouterr().out


def test_scan_single_port_with_nmap_warns_on_state_mismatch(capsys):
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["10.0.0.1"]
    scanner.__getitem__.return_value = {"tcp": {80: {"state": "filtered", "name": "http"}}}

    result = _scan_single_port_with_nmap(scanner, "10.0.0.1", 80)

    assert result["state"] == "filtered"  # nmap's state is still returned, just flagged
    out = capsys.readouterr().out
    assert "Warning" in out
    assert "filtered" in out


def test_scan_single_port_with_nmap_warns_when_port_missing_from_results(capsys):
    scanner = MagicMock()
    scanner.all_hosts.return_value = ["10.0.0.1"]
    scanner.__getitem__.return_value = {"tcp": {}}  # nmap's scan didn't report port 80 at all

    result = _scan_single_port_with_nmap(scanner, "10.0.0.1", 80)

    assert result["state"] == "unknown"
    assert "Warning" in capsys.readouterr().out


def test_scan_single_port_with_nmap_warns_when_host_missing_entirely(capsys):
    scanner = MagicMock()
    scanner.all_hosts.return_value = []  # nmap didn't see the host in this scan at all

    result = _scan_single_port_with_nmap(scanner, "10.0.0.1", 80)

    assert result["state"] == "unknown"
    assert "Warning" in capsys.readouterr().out
