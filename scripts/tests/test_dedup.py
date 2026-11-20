#!/usr/bin/env python3
"""
Unit tests for scripts/dedup.py -- the deterministic cross-agent de-duplication engine (P1-2).

Guarantee: the same bug reported by two agents on the same locus collapses to one entry deterministically
(canonical key = asset-host + normalized endpoint/param + vuln-class), the strongest is the primary, and a
genuinely different root cause on the same endpoint is NOT merged.

Stdlib only, runnable as `python test_dedup.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import threading
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


class ConcurrentFindingsWrite(unittest.TestCase):
    """Wave-2: the engine-core wave-merge persists deduped findings while concurrent hunters may also
    write. write_findings / update_findings are atomic + per-file-locked so neither clobbers the other."""

    def test_update_findings_stamps_duplicates_merge_safe(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "findings.json"
            a = F("RS-2026-001", "https://app.acme.com/o?id=1", sev="high")
            b = F("RS-2026-002", "https://app.acme.com/o?id=2", sev="medium")
            dedup.write_findings(p, [a, b])
            out = dedup.update_findings(p, lambda fs: dedup.apply_merges(fs)[0])
            self.assertIsNotNone(out)
            by = {f["id"]: f for f in json.loads(p.read_text(encoding="utf-8"))}
            self.assertEqual(by["RS-2026-002"]["status"], "duplicate")   # weaker -> duplicate
            self.assertNotEqual(by["RS-2026-001"].get("status"), "duplicate")

    def test_update_findings_absent_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(dedup.update_findings(pathlib.Path(d) / "nope.json", lambda fs: fs))

    def test_concurrent_appends_do_not_clobber(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "findings.json"
            dedup.write_findings(p, [])
            n = 8
            barrier = threading.Barrier(n)
            errors = []

            def worker(i):
                try:
                    barrier.wait(timeout=15)

                    def add(fs):
                        fs.append(F(f"RS-2026-{i:03d}", f"https://x.test/p{i}"))
                        return fs

                    dedup.update_findings(p, add)
                except Exception as e:             # noqa: BLE001
                    errors.append((i, repr(e)))

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            self.assertEqual(errors, [], errors)
            final = json.loads(p.read_text(encoding="utf-8"))           # valid JSON, nothing torn
            self.assertEqual(len({f["id"] for f in final}), n, "a concurrent append was clobbered")


if __name__ == "__main__":
    unittest.main()
