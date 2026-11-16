#!/usr/bin/env python3
"""
Unit tests for scripts/chain_validate.py -- the attack-chain integrity validator (P2-2).

Guarantee: a kill chain may only compose findings whose verdict is accepted/blocked, and a chain finding
(placed in the report's attack_chains[]) must be composite:true (else reporting double-counts it).

Stdlib only, runnable as `python test_chain_validate.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import chain_validate as cv  # noqa: E402

FINDINGS = {
    "RS-2026-001": {"id": "RS-2026-001", "review": {"verdict": "accepted"}},
    "RS-2026-002": {"id": "RS-2026-002", "status": "verified"},
    "RS-2026-003": {"id": "RS-2026-003", "review": {"verdict": "blocked"}},
    "RS-2026-009": {"id": "RS-2026-009", "review": {"verdict": "rejected"}},
}


class StepResolution(unittest.TestCase):
    def test_valid_chain_clean(self):
        chains = [{"id": "chain-001", "steps": [{"finding_id": "RS-2026-001"},
                                                {"finding_id": "RS-2026-002"}]}]
        self.assertEqual(cv.validate_chains(chains, FINDINGS), [])

    def test_blocked_is_reportable(self):
        chains = [{"id": "chain-002", "steps": [{"finding_id": "RS-2026-001"},
                                                {"finding_id": "RS-2026-003"}]}]
        self.assertEqual(cv.validate_chains(chains, FINDINGS), [])

    def test_rejected_step_fails(self):
        chains = [{"id": "chain-003", "steps": [{"finding_id": "RS-2026-001"},
                                                {"finding_id": "RS-2026-009"}]}]
        e = cv.validate_chains(chains, FINDINGS)
        self.assertTrue(any("RS-2026-009" in x for x in e))

    def test_unknown_step_fails(self):
        chains = [{"id": "c", "steps": [{"finding_id": "RS-2026-001"}, {"finding_id": "RS-2026-404"}]}]
        self.assertTrue(any("resolves to no finding" in x for x in cv.validate_chains(chains, FINDINGS)))

    def test_short_chain_fails(self):
        chains = [{"id": "c", "steps": [{"finding_id": "RS-2026-001"}]}]
        self.assertTrue(any("needs >= 2" in x for x in cv.validate_chains(chains, FINDINGS)))


class CompositeFlag(unittest.TestCase):
    def test_non_composite_chain_finding_fails(self):
        e = cv.validate_chains([], FINDINGS, chain_findings=[{"id": "RS-2026-050", "composite": False}])
        self.assertTrue(any("composite:true" in x for x in e))

    def test_composite_chain_finding_ok(self):
        self.assertEqual(
            cv.validate_chains([], FINDINGS, chain_findings=[{"id": "RS-2026-050", "composite": True}]), [])


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        cv.selftest()


if __name__ == "__main__":
    unittest.main()
