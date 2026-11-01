#!/usr/bin/env python3
"""
Unit tests for scripts/recall_audit.py -- the "what did we miss?" altitude (recall fix #4).

Guarantee: recall gaps no existing gate catches are surfaced — a class that ran but found nothing on
a recon-signalled surface with the escalation ladder unexhausted (shallow-clear), and a class skipped
despite a matching signal (skipped-but-signalled) — while legitimate clears stay silent.

Stdlib only, runnable as `python test_recall_audit.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import escalation as esc  # noqa: E402
import recall_audit as ra  # noqa: E402

MAPC = [
    {"id": "xss", "triggers": ["sink:html-reflect", "sink:dom", "param:any"]},
    {"id": "sqli", "triggers": ["param:injectable"]},
    {"id": "ssrf", "triggers": ["param:url-fetching"]},
    {"id": "secrets", "triggers": []},
]


class ShallowClear(unittest.TestCase):
    def test_empty_on_signalled_surface_is_a_gap(self):
        led = [{"id": "sqli", "status": "attempted", "findings_count": 0,
                "triggers_matched": ["param:injectable"]}]
        r = ra.audit(led, {"param:injectable"}, MAPC)
        self.assertEqual(r["gaps"][0]["type"], "shallow-clear")
        self.assertEqual(r["gaps"][0]["severity"], "high")
        self.assertIn("derive-not-assume", r["gaps"][0]["suggested_action"])

    def test_exhausted_ladder_is_not_a_gap(self):
        led = [{"id": "sqli", "status": "attempted", "findings_count": 0,
                "triggers_matched": ["param:injectable"]}]
        r = ra.audit(led, {"param:injectable"}, MAPC, escalations={"sqli": esc.ladder_for("sqli")})
        self.assertEqual(r["summary"]["total"], 0)

    def test_low_prior_empty_is_not_a_gap(self):
        led = [{"id": "ssrf", "status": "attempted", "findings_count": 0, "triggers_matched": []}]
        self.assertEqual(ra.audit(led, set(), MAPC)["summary"]["total"], 0)

    def test_signal_fallback_when_ledger_omits_triggers_matched(self):
        # no triggers_matched recorded, but the available signal matches the map -> still high-prior
        led = [{"id": "sqli", "status": "attempted", "findings_count": 0}]
        r = ra.audit(led, {"param:injectable"}, MAPC)
        self.assertEqual(r["gaps"][0]["type"], "shallow-clear")

    def test_found_class_is_never_a_gap(self):
        led = [{"id": "sqli", "status": "attempted", "findings_count": 2,
                "triggers_matched": ["param:injectable"]}]
        self.assertEqual(ra.audit(led, {"param:injectable"}, MAPC)["summary"]["total"], 0)


class SkipsAndPending(unittest.TestCase):
    def test_skipped_but_signalled_is_high_gap(self):
        led = [{"id": "xss", "status": "skipped", "reason": "no reflection seen"}]
        r = ra.audit(led, {"sink:dom"}, MAPC)
        self.assertEqual(r["gaps"][0]["type"], "skipped-but-signalled")
        self.assertEqual(r["gaps"][0]["severity"], "high")

    def test_legit_skip_no_signal_is_silent(self):
        led = [{"id": "xss", "status": "skipped", "reason": "no reflection, DOM sink, or injectable param"}]
        self.assertEqual(ra.audit(led, set(), MAPC)["summary"]["total"], 0)

    def test_weak_skip_reason_is_medium(self):
        led = [{"id": "xss", "status": "skipped", "reason": "n/a"}]
        r = ra.audit(led, set(), MAPC)
        self.assertEqual(r["gaps"][0]["type"], "weak-skip-reason")
        self.assertEqual(r["gaps"][0]["severity"], "medium")

    def test_pending_at_close_is_high_gap(self):
        led = [{"id": "sqli", "status": "pending"}]
        r = ra.audit(led, set(), MAPC)
        self.assertEqual(r["gaps"][0]["type"], "pending-at-close")

    def test_ranking_high_before_medium(self):
        led = [{"id": "xss", "status": "skipped", "reason": "x"},          # medium (weak reason)
               {"id": "sqli", "status": "pending"}]                         # high
        r = ra.audit(led, set(), MAPC)
        self.assertEqual(r["gaps"][0]["severity"], "high")


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        ra.selftest()


if __name__ == "__main__":
    unittest.main()
