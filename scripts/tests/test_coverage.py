#!/usr/bin/env python3
"""
Unit tests for scripts/coverage.py signal loading + deterministic routing.

Regression focus: `_load_signals` must accept the NESTED document the Redstrike
signals feeder emits — {"signals": [...], "signal_evidence": {...}, ...} — and use
its inner `signals` list, NOT the top-level keys. The old code took the top-level
keys of any dict as the signal set, so the feeder's documented shape silently
collapsed routing to baseline-only with no error.

Stdlib only, runnable as `python test_coverage.py` (the CI convention).
"""
import io
import json
import pathlib
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import coverage as c  # noqa: E402


def _write(tmp, obj):
    p = pathlib.Path(tmp) / "signals.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


class LoadSignals(unittest.TestCase):
    def test_bare_list(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(
                c._load_signals(_write(t, ["tech:wordpress", "param:injectable"])),
                {"tech:wordpress", "param:injectable"},
            )

    def test_flat_object_truthy(self):
        with tempfile.TemporaryDirectory() as t:
            got = c._load_signals(_write(t, {"tech:wordpress": True, "param:any": False}))
            self.assertEqual(got, {"tech:wordpress"})

    def test_nested_feeder_document(self):
        """THE regression: a feeder-shaped doc must yield its inner signals,
        never the wrapper keys ('signals', 'signal_evidence', ...)."""
        doc = {
            "_comment": "recon signals",
            "signals": ["tech:wordpress", "endpoint:api", "param:injectable"],
            "signal_evidence": {"tech:wordpress": "generator meta"},
            "surfaces_ruled_out": {"endpoint:https": "plain http"},
            "phases": ["web"],
        }
        with tempfile.TemporaryDirectory() as t:
            got = c._load_signals(_write(t, doc))
        self.assertEqual(got, {"tech:wordpress", "endpoint:api", "param:injectable"})
        # the wrapper keys must NOT leak in as signals
        for junk in ("signals", "signal_evidence", "surfaces_ruled_out", "phases", "_comment"):
            self.assertNotIn(junk, got)

    def test_nested_signals_as_object(self):
        doc = {"signals": {"tech:wordpress": True, "flow:auth": True, "x": False}}
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(
                c._load_signals(_write(t, doc)), {"tech:wordpress", "flow:auth"}
            )

    def test_flat_object_drops_meta_keys(self):
        """A mistakenly-flat feeder doc can't smuggle metadata keys in as signals."""
        doc = {"_comment": "x", "signal_evidence": {"a": 1}, "tech:wordpress": True}
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(c._load_signals(_write(t, doc)), {"tech:wordpress"})

    def test_none_is_recall_safe(self):
        self.assertIsNone(c._load_signals(None))


class RoutingFromNestedDoc(unittest.TestCase):
    """End-to-end: the nested doc must route exactly like the equivalent bare list,
    and must NOT collapse to baseline-only (the symptom of the bug)."""

    @classmethod
    def setUpClass(cls):
        cls.m = c.load_map()

    def _plan_ids(self, signals):
        led = c.plan(self.m, signals, {"web"})
        return {x["id"]: x["status"] for x in led["categories"]}

    def test_nested_equals_bare_list(self):
        sigs = ["tech:wordpress", "param:injectable", "endpoint:api",
                "objref:enumerable", "identities:multi"]
        doc = {"signals": sigs, "signal_evidence": {}, "phases": ["web"]}
        with tempfile.TemporaryDirectory() as t:
            from_doc = c._load_signals(_write(t, doc))
            from_list = c._load_signals(_write(t, sigs))
        self.assertEqual(from_doc, from_list)
        self.assertEqual(self._plan_ids(from_doc), self._plan_ids(from_list))

    def test_nested_doc_does_not_collapse_to_baseline(self):
        # With real signals, triggered non-baseline categories must be pending,
        # and untriggered ones skipped — NOT the all-skipped-but-baseline collapse.
        doc = {"signals": ["tech:wordpress", "param:injectable", "param:search"]}
        with tempfile.TemporaryDirectory() as t:
            sigs = c._load_signals(_write(t, doc))
        ids = self._plan_ids(sigs)
        self.assertEqual(ids.get("framework-wordpress"), "pending")  # tech:wordpress
        self.assertEqual(ids.get("sqli"), "pending")                 # param:injectable/search
        self.assertEqual(ids.get("ssrf"), "skipped")                 # no url-fetching signal
        # baseline still pending regardless
        self.assertEqual(ids.get("secrets"), "pending")

    def test_buggy_behaviour_would_have_collapsed(self):
        """Guard: feeding the wrapper KEYS (the old bug) routes nothing but baseline —
        proving the fix (using the inner list) is what prevents the collapse."""
        wrapper_keys = {"signals", "signal_evidence", "surfaces_ruled_out", "phases"}
        ids = self._plan_ids(wrapper_keys)
        self.assertEqual(ids.get("framework-wordpress"), "skipped")  # tech:wordpress NOT seen
        self.assertEqual(ids.get("sqli"), "skipped")


class FindingsCrossCheck(unittest.TestCase):
    """P2-5: the soft cross-check must fire on the REAL per-skill layout (<eng>/*/findings.json), not only
    a root findings.json (which almost never exists), so 'findings but no attempted category' is caught."""

    def _ledger_no_attempted(self, eng):
        m = c.load_map()
        led = c.plan(m, set(), {"web"})  # empty signals -> non-baseline web categories skip, nothing attempted
        for cat in led["categories"]:
            if cat["status"] == "attempted":
                cat["status"] = "pending"
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return m

    def test_per_skill_findings_trigger_the_cross_check(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            m = self._ledger_no_attempted(eng)
            (eng / "idor").mkdir()
            (eng / "idor" / "findings.json").write_text(
                json.dumps([{"id": "RS-2026-001", "title": "x"}]), encoding="utf-8")
            _ok, _lines, msgs = c.validate(eng, m, strict=False)
            self.assertTrue(any("no category is marked 'attempted'" in str(x) for x in msgs), msgs)

    def test_no_findings_no_crosscheck_warning(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            m = self._ledger_no_attempted(eng)
            _ok, _lines, msgs = c.validate(eng, m, strict=False)
            self.assertFalse(any("no category is marked 'attempted'" in str(x) for x in msgs), msgs)


class MarkEscalations(unittest.TestCase):
    """fix #3: persist escalation-ladder progress on the ledger entry so the recall-audit shallow-clear
    gate can tell an exhausted, honest clear from an untrustworthy first-payload clear."""

    def _plan(self, eng):
        m = c.load_map()
        led = c.plan(m, {"param:injectable"}, {"web"}, eng.name)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return m

    def test_escalations_merge_and_dedupe(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan(eng)
            c.mark(eng, "sqli", "attempted", count=0, escalations=["derive-not-assume", "encoding-ladder"])
            c.mark(eng, "sqli", "attempted", count=0, escalations=["encoding-ladder", "waf-bypass"])
            led = json.loads((eng / "coverage_ledger.json").read_text())
            sqli = next(x for x in led["categories"] if x["id"] == "sqli")
            self.assertEqual(sqli["escalations"], ["derive-not-assume", "encoding-ladder", "waf-bypass"])

    def test_full_ladder_clears_the_shallow_clear_gap(self):
        # end-to-end: an empty-but-signalled sqli is a shallow-clear gap UNTIL the ladder is recorded.
        import escalation as esc
        import recall_audit as ra
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan(eng)
            c.mark(eng, "sqli", "attempted", count=0)
            gaps_before = ra.load_and_audit(eng)["gaps"]
            self.assertTrue(any(g["type"] == "shallow-clear" and g["category"] == "sqli" for g in gaps_before))
            c.mark(eng, "sqli", "attempted", count=0, escalations=esc.ladder_for("sqli"))
            gaps_after = ra.load_and_audit(eng)["gaps"]
            self.assertFalse(any(g["type"] == "shallow-clear" and g["category"] == "sqli" for g in gaps_after))


class DepthSubstanceBar(unittest.TestCase):
    """Trust / no rubber-stamped recall: a zero-finding `attempted` clear may only count as COVERED when
    the mark PROVES depth (enough probe attempts + technique variants + a differential note / evidence
    pointer). A shallow 'attempted' is REJECTED by the completion gate and is re-drivable, not covered."""

    @classmethod
    def setUpClass(cls):
        cls.m = c.load_map()

    # --- pure substance check ------------------------------------------------
    def test_thresholds_default_and_per_class(self):
        # per-class override (sqli) layered over the map default; an unlisted class falls to default.
        self.assertEqual(c.depth_thresholds(self.m, "sqli"), {"min_attempts": 5, "min_variants": 2})
        self.assertEqual(c.depth_thresholds(self.m, "open-redirect"),
                         c.depth_thresholds({}, "open-redirect"))  # falls back to the built-in default
        self.assertEqual(c.depth_thresholds({}, "anything"), c._DEFAULT_DEPTH)

    def test_finding_is_self_evident_substance(self):
        # >=1 finding short-circuits the bar regardless of depth fields.
        self.assertIsNone(c.attempted_substance_gap({"id": "sqli", "findings_count": 1}, {"min_attempts": 99,
                                                                                          "min_variants": 99}))

    def test_zero_finding_bare_clear_is_a_gap(self):
        gap = c.attempted_substance_gap({"id": "sqli", "findings_count": 0}, {"min_attempts": 5,
                                                                              "min_variants": 2})
        self.assertIsNotNone(gap)
        self.assertIn("attempts 0/5", gap)
        self.assertIn("variants 0/2", gap)

    def test_zero_finding_full_depth_clears(self):
        entry = {"id": "sqli", "findings_count": 0, "attempts": 6,
                 "variants_tried": ["derive-not-assume", "encoding-ladder"],
                 "depth_note": "boolean/time/union differential all negative on id,q,search"}
        self.assertIsNone(c.attempted_substance_gap(entry, {"min_attempts": 5, "min_variants": 2}))

    def test_variants_union_with_escalations(self):
        # escalation-ladder ids count toward min_variants (union), and each is >=1 attempt.
        entry = {"id": "xss", "findings_count": 0,
                 "escalations": ["browser-render", "context-variants"],
                 "evidence": "nb://xss/2026-001"}
        self.assertIsNone(c.attempted_substance_gap(entry, {"min_attempts": 2, "min_variants": 2}))

    def test_note_or_evidence_required(self):
        # enough attempts + variants but NO note and NO evidence -> still a gap.
        entry = {"id": "xss", "findings_count": 0, "attempts": 9,
                 "variants_tried": ["a", "b", "c"]}
        gap = c.attempted_substance_gap(entry, {"min_attempts": 3, "min_variants": 2})
        self.assertIsNotNone(gap)
        self.assertIn("evidence pointer", gap)
        # ...adding an evidence pointer clears it.
        entry["evidence"] = "burp://sitemap/item/42"
        self.assertIsNone(c.attempted_substance_gap(entry, {"min_attempts": 3, "min_variants": 2}))

    def test_class_exempt_via_zero_thresholds(self):
        # a deterministic, config-level carve-out (not a per-mark bypass): {0,0} exempts the class.
        self.assertIsNone(c.attempted_substance_gap({"id": "x", "findings_count": 0},
                                                    {"min_attempts": 0, "min_variants": 0}))

    # --- the completion gate (validate) rejects + re-routes -------------------
    def _terminal_ledger(self, eng):
        """A full, GATE-PASSING ledger: every category in a terminal state (plan's skipped/n-a/pipeline,
        and any remaining pending downgraded to skipped-with-reason). Nothing attempted => validate passes,
        so a single flipped category isolates the depth-substance behaviour."""
        led = c.plan(self.m, set(), {"web"}, eng.name)
        for cat in led["categories"]:
            if cat["status"] == "pending":
                cat["status"] = "skipped"
                cat["reason"] = "test: forced terminal (not under test)"
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return led

    def _flip(self, eng, cid, **fields):
        led = json.loads((eng / "coverage_ledger.json").read_text())
        hit = next(x for x in led["categories"] if x["id"] == cid)
        hit.update(fields)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return led

    def test_gate_passes_clean_terminal_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            ok, _lines, _msgs = c.validate(eng, self.m, strict=False)
            self.assertTrue(ok, _msgs)

    def test_gate_rejects_hand_edited_shallow_attempted(self):
        # un-gameable: a hand-edited "status":"attempted" with no depth is RECOMPUTED and rejected.
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            led = self._flip(eng, "cors", status="attempted", findings_count=0)
            ok, _lines, msgs = c.validate(eng, self.m, strict=False)
            self.assertFalse(ok)
            self.assertTrue(any("'cors' is 'attempted'" in str(x) and "re-drivable" in str(x) for x in msgs), msgs)
            # it shows up as shallow + re-drivable
            self.assertIn("cors", c.shallow_attempted_ids(led, self.m))
            self.assertIn("cors", c.redrivable_ids(led, self.m))

    def test_gate_accepts_substantiated_clear(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            led = self._flip(eng, "cors", status="attempted", findings_count=0, attempts=4,
                             variants_tried=["null-origin", "evil-origin"],
                             depth_note="ACAO not reflected for arbitrary origins; ACAC never true")
            ok, _lines, _msgs = c.validate(eng, self.m, strict=False)
            self.assertTrue(ok, _msgs)
            self.assertNotIn("cors", c.shallow_attempted_ids(led, self.m))
            self.assertNotIn("cors", c.redrivable_ids(led, self.m))

    def test_gate_accepts_attempted_with_findings(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            self._flip(eng, "cors", status="attempted", findings_count=2)
            ok, _lines, _msgs = c.validate(eng, self.m, strict=False)
            self.assertTrue(ok, _msgs)

    def test_redrivable_includes_pending_blocked_and_shallow(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            self._flip(eng, "cors", status="attempted", findings_count=0)      # shallow
            self._flip(eng, "clickjacking", status="pending")                   # pending
            led = self._flip(eng, "secrets", status="blocked", reason="needs approval")  # blocked
            red = set(c.redrivable_ids(led, self.m))
            self.assertTrue({"cors", "clickjacking", "secrets"} <= red, red)

    # --- mark(): record payload + the --require-depth refusal -----------------
    def _plan_pending(self, eng):
        led = c.plan(self.m, None, {"web"}, eng.name)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")

    def test_mark_shallow_records_weaker_and_is_redrivable(self):
        # default mark (no --require-depth): records attempted but VISIBLY weaker, and the gate re-drives it.
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "sqli", "attempted", count=0)
            self.assertEqual(rc, 0)
            led = json.loads((eng / "coverage_ledger.json").read_text())
            sqli = next(x for x in led["categories"] if x["id"] == "sqli")
            self.assertEqual(sqli["status"], "attempted")
            self.assertFalse(sqli["depth_substantiated"])
            self.assertIn("sqli", c.shallow_attempted_ids(led, self.m))

    def test_mark_require_depth_refuses_and_leaves_redrivable(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "sqli", "attempted", count=0, require_depth=True)
            self.assertEqual(rc, 2)  # refused
            led = json.loads((eng / "coverage_ledger.json").read_text())
            sqli = next(x for x in led["categories"] if x["id"] == "sqli")
            # the flip NEVER landed — the category stays at its prior re-drivable status, not a shallow clear.
            self.assertEqual(sqli["status"], "pending")
            self.assertIn("sqli", c.redrivable_ids(led, self.m))

    def test_mark_require_depth_accepts_full_payload(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "sqli", "attempted", count=0, require_depth=True, attempts=6,
                            variants=["derive-not-assume", "encoding-ladder"],
                            depth_note="boolean+time+union differential all negative on id,q,search params")
            self.assertEqual(rc, 0)
            led = json.loads((eng / "coverage_ledger.json").read_text())
            sqli = next(x for x in led["categories"] if x["id"] == "sqli")
            self.assertEqual(sqli["status"], "attempted")
            self.assertTrue(sqli["depth_substantiated"])
            self.assertEqual(sqli["variants_tried"], ["derive-not-assume", "encoding-ladder"])
            self.assertNotIn("sqli", c.shallow_attempted_ids(led, self.m))

    def test_mark_with_findings_is_substantiated(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "sqli", "attempted", count=3, require_depth=True)  # findings => no payload needed
            self.assertEqual(rc, 0)
            led = json.loads((eng / "coverage_ledger.json").read_text())
            sqli = next(x for x in led["categories"] if x["id"] == "sqli")
            self.assertTrue(sqli["depth_substantiated"])


class ReconcileSubstance(unittest.TestCase):
    """close-write reconcile stamps a finding-backed flip as depth_substantiated (the finding is the proof),
    so the completion gate never re-drives a category that actually produced findings."""

    def test_reconcile_stamps_depth_substantiated(self):
        led = {"categories": [{"id": "code-audit", "status": "pending", "findings_count": 0}]}
        c.reconcile_counts(led, [{"id": "RS-1", "_rs_source_skill": "code-audit"}])
        ca = led["categories"][0]
        self.assertEqual(ca["status"], "attempted")
        self.assertTrue(ca["depth_substantiated"])
        self.assertEqual(c.shallow_attempted_ids(led, c.load_map()), [])


class FamilyBlockGranularity(unittest.TestCase):
    """QW2: a `blocked` row on a `pattern: family` category (auth/sqli/…, >1 sub-agents) must NAME which
    sub-agent(s)/host(s) are blocked. Un-named siblings stay pending (re-drivable), not silently covered —
    the near-missed-P1 where `auth` blocked on its OAuth leg masked the untested in-scope `jwt` surface.
    `mark()` refuses an un-named family block; `validate()` fails a hand-edited one."""

    @classmethod
    def setUpClass(cls):
        cls.m = c.load_map()

    def _plan_auth_pending(self, eng):
        # a ledger where auth is routed pending (flow:auth signal), ready to be blocked.
        led = c.plan(self.m, {"flow:auth"}, {"web"}, eng.name)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return led

    def test_family_agents_lookup(self):
        self.assertEqual(c.family_agents(self.m, "auth"), ["auth-bypass", "jwt", "oauth"])
        self.assertEqual(c.family_agents(self.m, "secrets"), [])        # single-agent -> not a family
        self.assertEqual(c.family_agents(self.m, "nonexistent"), [])

    def test_mark_family_blocked_without_naming_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_auth_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "auth", "blocked", note="session expired")   # names no sub-surface
            self.assertEqual(rc, 2)                                           # refused
            led = json.loads((eng / "coverage_ledger.json").read_text())
            auth = next(x for x in led["categories"] if x["id"] == "auth")
            # the flip never landed — auth stays at its prior (re-drivable) status, not silently blocked.
            self.assertEqual(auth["status"], "pending")
            self.assertNotIn("blocked_subsurfaces", auth)

    def test_mark_family_blocked_names_leg_and_siblings_stay_pending(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_auth_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "auth", "blocked", note="oauth leg host is out of scope",
                            blocked_subsurfaces=["oauth"])
            self.assertEqual(rc, 0)
            led = json.loads((eng / "coverage_ledger.json").read_text())
            auth = next(x for x in led["categories"] if x["id"] == "auth")
            self.assertEqual(auth["status"], "blocked")
            self.assertEqual(auth["blocked_subsurfaces"], ["oauth"])
            # the un-named siblings stay pending (still owed, NOT folded under the block).
            self.assertEqual(sorted(auth["pending_subsurfaces"]), ["auth-bypass", "jwt"])

    def test_mark_family_blocked_reason_naming_counts(self):
        # naming the leg in the prose reason (no --blocked-subsurfaces) also satisfies enumeration.
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._plan_auth_pending(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "auth", "blocked", note="blocked on the oauth delivery leg only")
            self.assertEqual(rc, 0)
            led = json.loads((eng / "coverage_ledger.json").read_text())
            auth = next(x for x in led["categories"] if x["id"] == "auth")
            self.assertEqual(auth["blocked_subsurfaces"], ["oauth"])
            self.assertEqual(sorted(auth["pending_subsurfaces"]), ["auth-bypass", "jwt"])

    def test_single_agent_blocked_is_unaffected(self):
        # a single-agent class (secrets) blocked needs only a reason — no sub-surface enumeration.
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            led = c.plan(self.m, None, {"web"}, eng.name)
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                rc = c.mark(eng, "secrets", "blocked", note="needs operator approval to validate")
            self.assertEqual(rc, 0)
            auth = next(x for x in json.loads((eng / "coverage_ledger.json").read_text())["categories"]
                        if x["id"] == "secrets")
            self.assertEqual(auth["status"], "blocked")
            self.assertNotIn("blocked_subsurfaces", auth)

    def _terminal_ledger(self, eng):
        led = c.plan(self.m, set(), {"web"}, eng.name)
        for cat in led["categories"]:
            if cat["status"] == "pending":
                cat["status"] = "skipped"
                cat["reason"] = "test: forced terminal (not under test)"
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return led

    def _flip(self, eng, cid, **fields):
        led = json.loads((eng / "coverage_ledger.json").read_text())
        hit = next(x for x in led["categories"] if x["id"] == cid)
        hit.update(fields)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return led

    def test_validate_rejects_hand_edited_unenumerated_family_block(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            self._flip(eng, "auth", status="blocked", reason="session expired")   # no leg named
            ok, _lines, msgs = c.validate(eng, self.m, strict=False)
            self.assertFalse(ok)
            self.assertTrue(any("family" in str(x) and "'auth'" in str(x) and "naming" in str(x)
                                for x in msgs), msgs)

    def test_validate_accepts_enumerated_family_block(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            self._flip(eng, "auth", status="blocked", reason="oauth leg OOS",
                       blocked_subsurfaces=["oauth"], pending_subsurfaces=["auth-bypass", "jwt"])
            ok, _lines, _msgs = c.validate(eng, self.m, strict=False)
            self.assertTrue(ok, _msgs)

    def test_validate_accepts_reason_named_family_block(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            self._flip(eng, "auth", status="blocked", reason="blocked on the oauth delivery leg")
            ok, _lines, _msgs = c.validate(eng, self.m, strict=False)
            self.assertTrue(ok, _msgs)

    def test_whole_surface_transport_block_is_exempt(self):
        # a disclosed WHOLE-surface block (diagnostics transport auto-populate: reason "transport: ...")
        # means nothing was reachable, so a family block there can't mask a sibling — no enumeration owed.
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._terminal_ledger(eng)
            self._flip(eng, "auth", status="blocked",
                       reason="transport: WAF block_rate 95% on app.acme.com (cloudflare)")
            ok, _lines, _msgs = c.validate(eng, self.m, strict=False)
            self.assertTrue(ok, _msgs)


class SelfTest(unittest.TestCase):
    def test_coverage_selftest_passes(self):
        self.assertEqual(c.selftest(), 0)


class ConcurrentWriters(unittest.TestCase):
    """Wave-2: the hunt fans out as concurrent subagents that --mark the ledger simultaneously. Atomic +
    locked writes mean every concurrent mark survives (no last-write-wins clobber) and the file never
    tears into invalid JSON."""

    def _seed(self, eng):
        m = c.load_map()
        led = c.plan(m, None, {"web"}, eng.name)   # no signals -> many 'pending' web categories
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        return [cat["id"] for cat in led["categories"] if cat["status"] == "pending"]

    def test_concurrent_marks_do_not_clobber(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ids = self._seed(eng)[:8]
            self.assertGreaterEqual(len(ids), 4, "need several pending categories to race")
            barrier = threading.Barrier(len(ids))
            errors = []

            def worker(cid):
                try:
                    barrier.wait(timeout=15)       # release all threads together -> maximal contention
                    c.mark(eng, cid, "attempted", count=1)
                except Exception as e:             # noqa: BLE001
                    errors.append((cid, repr(e)))

            threads = [threading.Thread(target=worker, args=(cid,)) for cid in ids]
            with redirect_stdout(io.StringIO()):   # mute the per-mark 'ok:' chatter
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=30)
            self.assertEqual(errors, [], errors)
            final = json.loads((eng / "coverage_ledger.json").read_text(encoding="utf-8"))  # valid JSON
            by = {cat["id"]: cat for cat in final["categories"]}
            for cid in ids:
                self.assertEqual(by[cid]["status"], "attempted", f"{cid} mark was clobbered")
                self.assertEqual(by[cid]["findings_count"], 1, f"{cid} count was clobbered")

    def test_update_ledger_merge_safe_path(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._seed(eng)

            def bump(led):
                led["categories"][0]["findings_count"] = 42
                return led

            out = c.update_ledger(eng, bump)
            self.assertIsNotNone(out)
            on_disk = json.loads((eng / "coverage_ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(on_disk["categories"][0]["findings_count"], 42)
            self.assertIn("generated_at", on_disk)

    def test_update_ledger_absent_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(c.update_ledger(pathlib.Path(d), lambda led: led))


if __name__ == "__main__":
    unittest.main(verbosity=2)
