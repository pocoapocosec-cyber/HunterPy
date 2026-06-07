"""Tests for the NVD client. Network is never actually contacted —
we patch the internal _request method to return canned NVD payloads.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from modules.custom._nvd_client import NVDClient, CVE, _RateLimiter


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "en", "value": "Apache HTTP Server 2.4.49 path traversal."},
                    {"lang": "es", "value": "ignored"},
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 7.5,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "baseSeverity": "HIGH",
                        },
                        "baseSeverity": "HIGH",
                    }]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-22"}]},
                ],
                "references": [
                    {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"},
                ],
                "published": "2021-10-05T19:15:00Z",
                "lastModified": "2022-04-04T14:00:00Z",
            }
        },
        {
            "cve": {
                "id": "CVE-2021-42013",
                "descriptions": [{"lang": "en", "value": "Bypass for CVE-2021-41773."}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8, "vectorString":
                                     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                     "baseSeverity": "CRITICAL"},
                        "baseSeverity": "CRITICAL",
                    }]
                },
                "references": [],
            }
        },
    ],
}


class TestNVDClientParsing(unittest.TestCase):
    def test_parses_response(self):
        cves = NVDClient._parse_nvd_response(SAMPLE_NVD_RESPONSE)
        self.assertEqual(len(cves), 2)
        # Sorted by CVSS descending
        self.assertEqual(cves[0].cve_id, "CVE-2021-42013")
        self.assertEqual(cves[0].cvss, 9.8)
        self.assertEqual(cves[0].severity, "CRITICAL")
        self.assertEqual(cves[1].cve_id, "CVE-2021-41773")
        self.assertIn("CWE-22", cves[1].cwe_ids)
        self.assertEqual(cves[1].exploit, "trivial")  # AV:N PR:N UI:N + CVSS 7.5

    def test_handles_empty_response(self):
        self.assertEqual(NVDClient._parse_nvd_response({"vulnerabilities": []}), [])
        self.assertEqual(NVDClient._parse_nvd_response({}), [])

    def test_exploit_heuristic(self):
        self.assertEqual(NVDClient._guess_exploit(9.0, "AV:N/PR:N/UI:N"), "trivial")
        self.assertEqual(NVDClient._guess_exploit(6.5, "AV:N/PR:L/UI:R"), "moderate")
        self.assertEqual(NVDClient._guess_exploit(3.0, "AV:L/PR:H/UI:R"), "difficult")

    def test_severity_labels(self):
        self.assertEqual(NVDClient._severity_label(9.5), "CRITICAL")
        self.assertEqual(NVDClient._severity_label(7.0), "HIGH")
        self.assertEqual(NVDClient._severity_label(4.0), "MEDIUM")
        self.assertEqual(NVDClient._severity_label(0.5), "LOW")
        self.assertEqual(NVDClient._severity_label(0.0), "UNKNOWN")


class TestNVDClientCaching(unittest.TestCase):
    def setUp(self):
        # isolated DB per test
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name

    def tearDown(self):
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_first_call_hits_network_second_uses_cache(self):
        client = NVDClient(db_path=self.db_path)
        with patch.object(client, "_request", return_value=SAMPLE_NVD_RESPONSE) as m:
            r1 = client.search_by_keyword("apache 2.4.49")
            r2 = client.search_by_keyword("apache 2.4.49")
        self.assertEqual(m.call_count, 1)         # cached on 2nd call
        self.assertEqual([c.cve_id for c in r1], [c.cve_id for c in r2])
        self.assertEqual(len(r1), 2)

    def test_offline_uses_static_fallback(self):
        client = NVDClient(db_path=self.db_path, offline=True)
        with patch.object(client, "_request") as m:
            cves = client.search_by_keyword("apache 2.4.41")
        m.assert_not_called()
        # static DB has Apache + Nginx + WordPress entries
        self.assertTrue(any("CVE" in c.cve_id for c in cves))
        self.assertTrue(all(c.source == "static" for c in cves))

    def test_network_error_falls_back_to_static(self):
        client = NVDClient(db_path=self.db_path)
        with patch.object(client, "_request", side_effect=RuntimeError("network down")):
            cves = client.search_by_keyword("apache 2.4.41")
        self.assertTrue(cves)
        self.assertTrue(all(c.source == "static" for c in cves))

    def test_min_cvss_filter(self):
        client = NVDClient(db_path=self.db_path)
        with patch.object(client, "_request", return_value=SAMPLE_NVD_RESPONSE):
            cves = client.search_by_keyword("apache", min_cvss=9.0)
        self.assertEqual([c.cve_id for c in cves], ["CVE-2021-42013"])

    def test_get_cve_validates_id_format(self):
        client = NVDClient(db_path=self.db_path, offline=True)
        with self.assertRaises(ValueError):
            client.get_cve("not-a-cve")

    def test_clear_cache(self):
        client = NVDClient(db_path=self.db_path)
        with patch.object(client, "_request", return_value=SAMPLE_NVD_RESPONSE) as m:
            client.search_by_keyword("apache")
            client.clear_cache()
            client.search_by_keyword("apache")
        self.assertEqual(m.call_count, 2)         # cache wiped → hit again


class TestRateLimiter(unittest.TestCase):
    def test_allows_burst_under_limit(self):
        rl = _RateLimiter(max_calls=3, period_sec=10)
        for _ in range(3):
            rl.acquire()      # should not block
        self.assertEqual(len(rl.events), 3)

    def test_blocks_when_over_limit(self):
        import time as _t
        rl = _RateLimiter(max_calls=2, period_sec=0.3)
        rl.acquire(); rl.acquire()
        start = _t.monotonic()
        rl.acquire()                              # must wait ~0.3s
        elapsed = _t.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.25)


if __name__ == "__main__":
    unittest.main()
