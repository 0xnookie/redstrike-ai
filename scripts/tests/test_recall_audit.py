#!/usr/bin/env python3
"""
Unit tests for scripts/recall_audit.py -- the "what did we miss?" altitude (recall fix #4).

Guarantee: recall gaps no existing gate catches are surfaced — a class that ran but found nothing on
a recon-signalled surface with the escalation ladder unexhausted (shallow-clear), and a class skipped
despite a matching signal (skipped-but-signalled) — while legitimate clears stay silent.

Stdlib only, runnable as `python test_recall_audit.py` (the CI convention).
"""
import json
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
    {"id": "injection", "triggers": ["sink:template", "sink:command", "param:injectable"]},
    {"id": "secrets", "triggers": []},
    # `auth` is a pattern:family with >1 sub-agents — the near-missed-P1 shape (one leg blocked masks a
    # sibling). `race-condition` is a single-agent class used to check the non-family blocked path.
    {"id": "auth", "triggers": ["flow:auth"], "pattern": "family",
     "agents": ["auth-bypass", "jwt", "oauth"]},
    {"id": "race-condition", "triggers": ["flow:state-change"], "pattern": "single",
     "agents": ["race-condition"]},
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


class SinkClassBlackBox(unittest.TestCase):
    """fix #4: a server-side-sink class (ssti/command-injection/deserialization, under `injection`) gated by
    sink:template/sink:command can't be SEEN black-box, so a no-signal skip is recon blindness — a MEDIUM gap."""

    def test_blackbox_sink_skip_is_medium_gap(self):
        led = [{"id": "injection", "status": "skipped",
                "reason": "no template/command/deserialization sink surfaced"}]
        r = ra.audit(led, set(), MAPC)
        g = next(x for x in r["gaps"] if x["category"] == "injection")
        self.assertEqual(g["type"], "sink-class-skipped-blackbox")
        self.assertEqual(g["severity"], "medium")

    def test_whitebox_skip_is_trustworthy(self):
        led = [{"id": "injection", "status": "skipped", "reason": "source reviewed; no sink reaches input"}]
        self.assertEqual(ra.audit(led, {"source:available"}, MAPC)["summary"]["total"], 0)

    def test_sink_signal_present_is_skipped_but_signalled_not_this(self):
        # if a sink signal IS available but the class was skipped, that's the HIGH skipped-but-signalled gap.
        led = [{"id": "injection", "status": "skipped", "reason": "x"}]
        r = ra.audit(led, {"sink:template"}, MAPC)
        self.assertTrue(any(g["type"] == "skipped-but-signalled" for g in r["gaps"]))
        self.assertFalse(any(g["type"] == "sink-class-skipped-blackbox" for g in r["gaps"]))

    def test_non_sink_class_skip_stays_silent(self):
        led = [{"id": "ssrf", "status": "skipped", "reason": "no URL-fetching parameter surfaced"}]
        self.assertEqual(ra.audit(led, set(), MAPC)["summary"]["total"], 0)


class BlockedBranch(unittest.TestCase):
    """QW1: a `blocked` row was a double blind spot — coverage.py treats only `pending` as open, and this
    engine had no `blocked` branch, so a family block on an out-of-scope leg masked an untested in-scope
    sibling (the near-missed-P1). A recon-signalled `blocked` class is a `blocked-unverified` HIGH gap
    UNLESS it both enumerates the blocked sub-surface(s) AND records that non-destructive detection ran."""

    def test_signalled_blocked_family_unenumerated_is_high_gap(self):
        led = [{"id": "auth", "status": "blocked", "reason": "session expired",
                "triggers_matched": ["flow:auth"]}]
        r = ra.audit(led, {"flow:auth"}, MAPC)
        g = next(x for x in r["gaps"] if x["category"] == "auth")
        self.assertEqual(g["type"], "blocked-unverified")
        self.assertEqual(g["severity"], "high")

    def test_honest_block_named_leg_plus_detection_is_not_a_gap(self):
        # names the blocked leg (oauth) AND records detection ran (32 forge attempts) -> trustworthy clear.
        led = [{"id": "auth", "status": "blocked", "triggers_matched": ["flow:auth"],
                "blocked_subsurfaces": ["oauth"], "attempts": 32,
                "reason": "oauth leg OOS; jwt + auth-bypass forge battery ran, all 32 rejected"}]
        self.assertEqual(ra.audit(led, {"flow:auth"}, MAPC)["summary"]["total"], 0)

    def test_named_leg_but_no_detection_is_still_a_gap(self):
        # enumerates oauth as blocked but shows NO detection on the siblings -> still a gap (the mask).
        led = [{"id": "auth", "status": "blocked", "triggers_matched": ["flow:auth"],
                "blocked_subsurfaces": ["oauth"], "reason": "oauth leg OOS"}]
        r = ra.audit(led, {"flow:auth"}, MAPC)
        g = next(x for x in r["gaps"] if x["category"] == "auth")
        self.assertEqual(g["type"], "blocked-unverified")
        self.assertIn("detection", g["detail"])

    def test_still_owed_siblings_surface_in_detail(self):
        led = [{"id": "auth", "status": "blocked", "triggers_matched": ["flow:auth"],
                "blocked_subsurfaces": ["oauth"], "pending_subsurfaces": ["auth-bypass", "jwt"],
                "reason": "oauth leg OOS"}]
        r = ra.audit(led, {"flow:auth"}, MAPC)
        g = next(x for x in r["gaps"] if x["category"] == "auth")
        self.assertIn("jwt", g["detail"])

    def test_low_prior_blocked_is_silent(self):
        # no recorded trigger and no matching signal -> recon never flagged it; no false positive.
        led = [{"id": "auth", "status": "blocked", "reason": "x"}]
        self.assertEqual(ra.audit(led, set(), MAPC)["summary"]["total"], 0)

    def test_whole_surface_transport_block_is_exempt(self):
        # a disclosed whole-surface transport block (host/WAF down) can't mask a reachable sibling.
        led = [{"id": "auth", "status": "blocked", "triggers_matched": ["flow:auth"],
                "reason": "transport: WAF block_rate 95% on app.acme.com (cloudflare)"}]
        self.assertEqual(ra.audit(led, {"flow:auth"}, MAPC)["summary"]["total"], 0)

    def test_nonfamily_blocked_with_detection_is_not_a_gap(self):
        # a single-agent class: a substantive reason enumerates the one surface; detection recorded -> ok.
        led = [{"id": "race-condition", "status": "blocked", "triggers_matched": ["flow:state-change"],
                "attempts": 4, "reason": "single-use endpoint; 4 parallel bursts, no over-issue observed"}]
        self.assertEqual(ra.audit(led, {"flow:state-change"}, MAPC)["summary"]["total"], 0)


class BlockedAccept(unittest.TestCase):
    """An honest block that genuinely can't be closed in-scope is routed through the SAME accept mechanism
    as a shallow-clear (write_accept + a named _BLOCKER_VOCAB blocker) — no new escape hatch. The new
    `oauth-leg-oos` / `session-expired` blockers name why a family leg is unclosable."""

    def _blocked_eng(self):
        import json as _json
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        eng = pathlib.Path(self._tmp.name)
        # load_and_audit uses the REAL routing map (auth is a family there); triggers_matched makes it
        # high-prior, so the blocked branch flags blocked-unverified:auth.
        (eng / "coverage_ledger.json").write_text(_json.dumps(
            {"categories": [{"id": "auth", "status": "blocked", "reason": "session expired",
                             "triggers_matched": ["flow:auth"]}]}), encoding="utf-8")
        return eng

    def test_engine_flags_blocked_unverified_for_real_map(self):
        eng = self._blocked_eng()
        res = ra.load_and_audit(eng)
        self.assertTrue(any(g["type"] == "blocked-unverified" and g["category"] == "auth"
                            for g in res["gaps"]), res["gaps"])

    def test_accept_blocked_gap_with_named_blocker(self):
        eng = self._blocked_eng()
        ok, msg = ra.write_accept(eng, "blocked-unverified:auth", blockers=["oauth-leg-oos"],
                                  ladder_run=[], reason="oauth delivery host auth.example.com is out of scope")
        self.assertTrue(ok, msg)
        data = json.loads((eng / "reviews" / "recall_audit_accepts.json").read_text(encoding="utf-8"))
        self.assertEqual(data[0]["id"], "blocked-unverified:auth")
        self.assertEqual(data[0]["blocker"], ["oauth-leg-oos"])
        # a blocked accept needs NO ladder-run (that's a shallow-clear-only requirement).
        self.assertNotIn("ladder_run", data[0])

    def test_accept_requires_named_blocker(self):
        eng = self._blocked_eng()
        ok, msg = ra.write_accept(eng, "blocked-unverified:auth", blockers=[], ladder_run=[], reason="x")
        self.assertFalse(ok)
        self.assertIn("--blocker is required", msg)


class AcceptWriter(unittest.TestCase):
    """The honest-accept writer (`--accept`): records an accept ONLY for a gap the deterministic engine
    actually flags, ONLY with a named environmental blocker from the closed vocab, and (for a shallow-clear)
    ONLY alongside the real escalation techniques that ran — writing the LIST shape the gate already reads."""

    def _shallow_eng(self, *, found=0):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        eng = pathlib.Path(self._tmp.name)
        import json as _json
        (eng / "coverage_ledger.json").write_text(_json.dumps(
            {"categories": [{"id": "sqli", "status": "attempted", "findings_count": found,
                             "triggers_matched": ["param:injectable"]}]}), encoding="utf-8")
        return eng

    def _accepts(self, eng):
        import json as _json
        return _json.loads((eng / "reviews" / "recall_audit_accepts.json").read_text(encoding="utf-8"))

    def test_writes_accept_in_list_shape(self):
        eng = self._shallow_eng()
        ladder = esc.ladder_for("sqli")[:2]
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=["opaque-session"],
                                  ladder_run=ladder, reason="unseeded test DB, no rows to extract")
        self.assertTrue(ok, msg)
        data = self._accepts(eng)
        self.assertIsInstance(data, list)
        e = data[0]
        self.assertEqual(e["id"], "shallow-clear:sqli")
        self.assertTrue(e["reason"].strip())           # reader keys on id + non-empty reason
        self.assertEqual(e["blocker"], ["opaque-session"])
        self.assertEqual(e["ladder_run"], ladder)

    def test_refuse_non_gap(self):
        eng = self._shallow_eng(found=2)               # sqli HAS findings -> not a gap
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=["opaque-session"],
                                  ladder_run=esc.ladder_for("sqli"), reason="x")
        self.assertFalse(ok)
        self.assertIn("does not currently flag", msg)
        self.assertFalse((eng / "reviews" / "recall_audit_accepts.json").exists())

    def test_refuse_missing_blocker(self):
        eng = self._shallow_eng()
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=[],
                                  ladder_run=esc.ladder_for("sqli"), reason="x")
        self.assertFalse(ok)
        self.assertIn("--blocker is required", msg)

    def test_refuse_blocker_off_vocab(self):
        eng = self._shallow_eng()
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=["made-up-reason"],
                                  ladder_run=esc.ladder_for("sqli"), reason="x")
        self.assertFalse(ok)
        self.assertIn("unknown --blocker", msg)

    def test_refuse_shallow_clear_without_ladder_run(self):
        eng = self._shallow_eng()
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=["opaque-session"],
                                  ladder_run=[], reason="x")
        self.assertFalse(ok)
        self.assertIn("--ladder-run is required", msg)

    def test_refuse_ladder_technique_off_ladder(self):
        eng = self._shallow_eng()
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=["opaque-session"],
                                  ladder_run=["not-a-real-technique"], reason="x")
        self.assertFalse(ok)
        self.assertIn("not in", msg)

    def test_refuse_blank_reason(self):
        eng = self._shallow_eng()
        ok, msg = ra.write_accept(eng, "shallow-clear:sqli", blockers=["opaque-session"],
                                  ladder_run=esc.ladder_for("sqli"), reason="   ")
        self.assertFalse(ok)
        self.assertIn("--reason is required", msg)

    def test_idempotent_replace_same_id(self):
        eng = self._shallow_eng()
        ladder = esc.ladder_for("sqli")
        ra.write_accept(eng, "shallow-clear:sqli", blockers=["opaque-session"],
                        ladder_run=ladder, reason="first")
        ra.write_accept(eng, "shallow-clear:sqli", blockers=["single-identity"],
                        ladder_run=ladder, reason="second")
        data = self._accepts(eng)
        self.assertEqual(len(data), 1)                 # replaced, not duplicated
        self.assertEqual(data[0]["reason"], "second")


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        ra.selftest()


if __name__ == "__main__":
    unittest.main()
