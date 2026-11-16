#!/usr/bin/env python3
"""
Drift guard for the hypothesis-driven-depth contract extension (agentic upgrade #2).

These are prose/methodology changes, so the guard is a contract-presence test (as validate.py already
does for other load-bearing doc sections): the hypothesis layer must stay wired into all three places it
has to live, or the recall property it buys silently rots:

  - hunter-base.md : forms target-specific hypotheses ABOVE the ladder FLOOR and logs each to
                     hypotheses.jsonl (hypothesis -> test -> outcome); an unresolved one is an open-proof-gap.
  - escalation.md  : the ladder is the FLOOR, not the ceiling; an unresolved hypothesis == an open-proof-gap,
                     same as an un-exhausted ladder step; a surface with one cannot close clean.
  - verify-base.md : check #5 (coverage audit) treats an unresolved hypothesis as an open-proof-gap so it
                     can't read as a clean clear.

Stdlib only, runnable as `python test_hypothesis_depth.py`.
"""
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve()
CONTRACT = HERE.parents[1]


def _read(name):
    return (CONTRACT / name).read_text(encoding="utf-8", errors="replace")


class HunterBase(unittest.TestCase):
    def setUp(self):
        self.t = _read("hunter-base.md")
        self.low = self.t.lower()

    def test_section_present(self):
        self.assertIn("Hypothesis-driven depth", self.t)

    def test_floor_kept_intact(self):
        # the deterministic ladder stays the FLOOR, hypotheses are the layer above it
        self.assertIn("floor", self.low)
        self.assertIn("layer above", self.low)

    def test_structured_log_record(self):
        self.assertIn("hypotheses.jsonl", self.t)
        for field in ('"hypothesis"', '"test"', '"outcome"'):
            self.assertIn(field, self.t, f"the logged record shape must show {field}")

    def test_unresolved_is_open_proof_gap(self):
        self.assertIn("unresolved", self.low)
        self.assertIn("open-proof-gap", self.low)

    def test_no_new_payload_content_claim(self):
        # the extension is explicitly about STRUCTURE/LOGGING, adding no new offensive payloads
        self.assertIn("no new payloads", self.low)

    def test_listed_in_outputs(self):
        # hypotheses.jsonl is a declared shared output, not an undocumented side file
        self.assertIn("hypotheses.jsonl", self.t.split("## Shared outputs", 1)[-1])


class Escalation(unittest.TestCase):
    def setUp(self):
        self.t = _read("escalation.md")
        self.low = self.t.lower()

    def test_ladder_is_floor_not_ceiling(self):
        self.assertIn("floor", self.low)
        self.assertIn("not the ceiling", self.low)

    def test_hypothesis_layer_referenced(self):
        self.assertIn("hypotheses.jsonl", self.t)
        self.assertIn("hunter-base.md", self.t)

    def test_unresolved_equals_open_proof_gap(self):
        self.assertIn("unresolved", self.low)
        self.assertIn("open-proof-gap", self.low)
        # it can't close clean while a hypothesis is outstanding
        self.assertIn("shallow clear", self.low)


class VerifyBase(unittest.TestCase):
    def setUp(self):
        self.t = _read("verify-base.md")
        self.low = self.t.lower()

    def test_check5_audits_hypotheses(self):
        # check #5 (coverage audit) must now audit hypotheses.jsonl
        self.assertIn("hypotheses.jsonl", self.t)

    def test_unresolved_blocks_clean_clear(self):
        self.assertIn("unresolved", self.low)
        self.assertIn("open-proof-gap", self.low)
        self.assertIn("cannot read as a clean clear", self.low)


if __name__ == "__main__":
    unittest.main()
