#!/usr/bin/env python3
"""
Unit tests for scripts/dedup.py -- the deterministic cross-agent de-duplication engine (P1-2).

Guarantee: the same bug reported by two agents on the same locus collapses to one entry deterministically
(canonical key = asset-host + normalized endpoint/param + vuln-class), the strongest is the primary, and a
genuinely different root cause on the same endpoint is NOT merged.

Stdlib only, runnable as `python test_dedup.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import dedup  # noqa: E402


def F(fid, asset, cwe="CWE-639", sev="high", conf="confirmed", ev=1, **over):
    f = {"id": fid, "asset": asset, "category": {"cwe": cwe}, "severity": sev, "confidence": conf,
         "evidence": [{"type": "log", "ref": f"r{i}"} for i in range(ev)]}
    f.update(over)
    return f


class CanonicalKey(unittest.TestCase):
    def test_scheme_port_case_trailing_slash_are_normalized(self):
        a = F("RS-2026-001", "https://App.ACME.com:443/api/orders/?id=1")
        b = F("RS-2026-002", "http://app.acme.com/api/orders?id=2")
        self.assertEqual(dedup.canonical_key(a), dedup.canonical_key(b))

    def test_different_param_name_is_a_different_locus(self):
        a = F("RS-2026-001", "https://app.acme.com/o?id=1")
        b = F("RS-2026-002", "https://app.acme.com/o?sort=1")
        self.assertNotEqual(dedup.canonical_key(a), dedup.canonical_key(b))

    def test_different_class_is_not_merged(self):
        a = F("RS-2026-001", "https://app.acme.com/o?id=1", cwe="CWE-639")
        b = F("RS-2026-002", "https://app.acme.com/o?id=1", cwe="CWE-285")
        self.assertNotEqual(dedup.canonical_key(a), dedup.canonical_key(b))

    def test_owasp_fallback_when_no_cwe(self):
        a = {"id": "RS-2026-001", "asset": "https://app.acme.com/o", "category": {"owasp": "A01"},
             "severity": "high", "confidence": "confirmed", "evidence": [{"type": "log", "ref": "x"}]}
        b = {"id": "RS-2026-002", "asset": "https://app.acme.com/o", "category": {"owasp": "A01"},
             "severity": "low", "confidence": "tentative", "evidence": [{"type": "log", "ref": "y"}]}
        self.assertEqual(dedup.canonical_key(a), dedup.canonical_key(b))


class ProposeAndApply(unittest.TestCase):
    def test_strongest_is_primary_and_rest_are_duplicates(self):
        a = F("RS-2026-001", "https://app.acme.com/o?id=1", sev="high", ev=2)
        b = F("RS-2026-002", "https://app.acme.com/o?id=2", sev="medium", ev=1)
        merges = dedup.propose_merges([a, b])
        self.assertEqual(len(merges), 1)
        self.assertEqual(merges[0]["primary"], "RS-2026-001")
        self.assertEqual(merges[0]["duplicates"], ["RS-2026-002"])

    def test_apply_sets_duplicate_status_only_on_non_primary(self):
        a = F("RS-2026-001", "https://app.acme.com/o?id=1", sev="high")
        b = F("RS-2026-002", "https://app.acme.com/o?id=2", sev="medium")
        findings, mm = dedup.apply_merges([a, b])
        by = {f["id"]: f for f in findings}
        self.assertEqual(by["RS-2026-002"]["status"], "duplicate")
        self.assertNotEqual(by["RS-2026-001"].get("status"), "duplicate")
        self.assertEqual(mm, {"RS-2026-002": "RS-2026-001"})

    def test_tie_breaks_on_smallest_id_and_is_order_independent(self):
        a = F("RS-2026-020", "https://x.test/p", cwe="CWE-79")
        b = F("RS-2026-010", "https://x.test/p", cwe="CWE-79")
        self.assertEqual(dedup.propose_merges([a, b]), dedup.propose_merges([b, a]))
        self.assertEqual(dedup.propose_merges([a, b])[0]["primary"], "RS-2026-010")

    def test_composite_never_merged(self):
        a = F("RS-2026-010", "https://x.test/p", cwe="CWE-79")
        comp = F("RS-2026-030", "https://x.test/p", cwe="CWE-79", sev="critical", composite=True)
        merges = dedup.propose_merges([a, comp])
        self.assertEqual(merges, [])  # only one non-composite member -> no merge

    def test_lone_finding_is_not_a_merge(self):
        self.assertEqual(dedup.propose_merges([F("RS-2026-001", "https://x.test/p")]), [])


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        dedup.selftest()


if __name__ == "__main__":
    unittest.main()
