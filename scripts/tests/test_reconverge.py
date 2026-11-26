#!/usr/bin/env python3
"""
Unit tests for scripts/reconverge.py -- finding -> recon re-convergence (recall fix #6).

Regression focus: surface DISCOVERED DURING the hunt (an SSRF reaching an internal host, an
auth bypass yielding a second identity, a config leak exposing new endpoints) must re-open the
classes it now routes to, and the engagement is only DONE at the fixpoint -- a pass that adds
nothing new. The loop must always terminate (monotone work-list).

Stdlib only, runnable as `python test_reconverge.py` (the CI convention).
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import reconverge as rc  # noqa: E402

MAPC = [
    {"id": "xss", "phase": "web", "triggers": ["sink:html-reflect", "sink:dom", "param:any"]},
    {"id": "sqli", "phase": "web", "triggers": ["param:injectable"]},
    {"id": "ssrf", "phase": "web", "triggers": ["param:url-fetching"]},
    {"id": "cloud", "phase": "cloud", "triggers": ["asset:cloud"]},
    {"id": "authz", "phase": "web", "triggers": ["identity:multi"]},
    {"id": "exposed-surface", "phase": "web", "triggers": []},
]
MAPP = {"cloud": {"auto_on": "asset:cloud"}, "web3": {"auto_on": "asset:smart-contract"}}


def _trig(cid):
    return next((c["triggers"] for c in MAPC if c["id"] == cid), [])


class SignalDrivenReopen(unittest.TestCase):
    def test_new_signal_reopens_attempted_class(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")}]
        p = rc.reconverge(set(), set(), cats,
                          [{"source": "js", "signals": ["param:url-fetching"]}], MAPC, MAPP)
        self.assertEqual({r["id"] for r in p["reopen"]}, {"ssrf"})
        self.assertFalse(p["converged"])

    def test_new_identity_reopens_skipped_authz(self):
        cats = [{"id": "authz", "status": "skipped", "reason": "one identity", "triggers": _trig("authz")}]
        p = rc.reconverge(set(), set(), cats,
                          [{"source": "auth-bypass", "signals": ["identity:multi"]}], MAPC, MAPP)
        self.assertEqual([r["id"] for r in p["reopen"]], ["authz"])
        self.assertEqual(p["reopen"][0]["from_status"], "skipped")

    def test_pending_class_is_not_reopened(self):
        cats = [{"id": "sqli", "status": "pending", "triggers": _trig("sqli")}]
        p = rc.reconverge(set(), set(), cats, [{"signals": ["param:injectable"]}], MAPC, MAPP)
        self.assertEqual(p["reopen"], [])

    def test_already_seen_signal_is_no_delta(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")}]
        p = rc.reconverge({"param:url-fetching"}, set(), cats,
                          [{"signals": ["param:url-fetching"]}], MAPC, MAPP)
        self.assertTrue(p["converged"])
        self.assertEqual(p["reopen"], [])


class SurfaceDrivenReopen(unittest.TestCase):
    def test_new_endpoint_reopens_exposed_surface(self):
        cats = [{"id": "exposed-surface", "status": "attempted"}]
        p = rc.reconverge(set(), set(), cats,
                          [{"source": "ssrf", "surface": [{"kind": "endpoint", "value": "http://10.0.0.5/"}]}],
                          MAPC, MAPP)
        self.assertIn("exposed-surface", {r["id"] for r in p["reopen"]})
        self.assertEqual(len(p["added_surface"]), 1)

    def test_unrouted_surface_recorded_but_no_reopen(self):
        p = rc.reconverge(set(), set(), [{"id": "xss", "status": "attempted"}],
                          [{"surface": [{"kind": "weird-kind", "value": "x"}]}], MAPC, MAPP)
        self.assertTrue(p["added_surface_unrouted"])
        self.assertEqual(p["reopen"], [])
        self.assertFalse(p["converged"])


class ScopeSafety(unittest.TestCase):
    def test_out_of_phase_class_is_replan_candidate_not_reopened(self):
        cats = [{"id": "cloud", "status": "n/a", "reason": "cloud phase not in scope", "triggers": _trig("cloud")}]
        p = rc.reconverge(set(), set(), cats, [{"signals": ["asset:cloud"]}], MAPC, MAPP)
        self.assertEqual(p["reopen"], [])  # never auto-activate an out-of-scope phase
        self.assertEqual([c["id"] for c in p["replan_candidates"]], ["cloud"])
        self.assertIn("cloud", p["replan_phases"])


class Fixpoint(unittest.TestCase):
    def test_nothing_discovered_is_converged(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")}]
        self.assertTrue(rc.reconverge({"param:url-fetching"}, set(), cats, [], MAPC, MAPP)["converged"])

    def test_apply_then_reconverge_terminates(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")},
                {"id": "exposed-surface", "status": "attempted"}]
        obs = [{"source": "ssrf", "signals": ["param:url-fetching"],
                "surface": [{"kind": "endpoint", "value": "http://10.0.0.5/"}]}]
        p = rc.reconverge(set(), set(), cats, obs, MAPC, MAPP)
        self.assertFalse(p["converged"])
        cov = {"categories": [dict(c) for c in cats], "signals_used": []}
        surf = {"engagement": "demo", "surfaces": []}
        rc.apply_plan(cov, surf, p)
        # the applied ledger: reopened -> pending, signal seen, surface recorded
        ssrf = next(c for c in cov["categories"] if c["id"] == "ssrf")
        self.assertEqual(ssrf["status"], "pending")
        self.assertEqual(ssrf["reopened_rounds"], 1)
        self.assertIn("param:url-fetching", cov["signals_used"])
        self.assertTrue(surf["surfaces"])
        # a second pass over the SAME inbox now converges (the delta is empty)
        seen = set(cov["signals_used"])
        skeys = {(s["kind"], s["value"]) for s in surf["surfaces"]}
        applied = [{"id": c["id"], "status": c["status"], "triggers": _trig(c["id"])} for c in cov["categories"]]
        self.assertTrue(rc.reconverge(seen, skeys, applied, obs, MAPC, MAPP)["converged"])


class IngestValidation(unittest.TestCase):
    """P0-1: the inbox is validated at ingest — an out-of-vocab signal / unknown surface kind is REJECTED
    (quarantined), never folded into the ledgers (the sink:dom-backlink leak). A `content` discovery is NOT
    garbage: it ROUTES to content-discovery for URL/objref extraction (fix #5)."""
    VOCAB = {"param:url-fetching", "asset:cloud"}
    KINDS = {"param", "endpoint"}
    FROUTES = {"content": "content-discovery"}

    def test_split_keeps_valid_drops_invalid_reroutes_content(self):
        recs = [{"source": "pp", "signals": ["sink:dom-backlink", "param:url-fetching"],
                 "surface": [{"kind": "param", "value": "from"}, {"kind": "content", "value": "/x.xml"}]}]
        clean, rej, fu = rc.split_observations(recs, self.VOCAB, self.KINDS, self.FROUTES)
        self.assertEqual(clean[0]["signals"], ["param:url-fetching"])
        self.assertEqual([s["value"] for s in clean[0]["surface"]], ["from"])
        self.assertIn("sink:dom-backlink", rej[0]["rejected_signals"])
        # content is a followup, NOT rejected garbage
        self.assertFalse(rej[0]["rejected_surface"])
        self.assertEqual([f["value"] for f in fu], ["/x.xml"])
        self.assertEqual(fu[0]["route_to"], "content-discovery")

    def test_truly_unknown_kind_still_rejected(self):
        recs = [{"source": "x", "surface": [{"kind": "contnet", "value": "/x"}]}]
        _c, rej, fu = rc.split_observations(recs, self.VOCAB, self.KINDS, self.FROUTES)
        self.assertEqual(fu, [])
        self.assertTrue(any(b.get("kind") == "contnet" for b in rej[0]["rejected_surface"]))

    def test_fail_open_on_empty_vocab(self):
        recs = [{"signals": ["anything:at-all"]}]
        clean, rej, fu = rc.split_observations(recs, set(), set(), self.FROUTES)
        self.assertEqual(rej, [])
        self.assertEqual(clean[0]["signals"], ["anything:at-all"])

    def test_record_with_only_invalid_parts_yields_no_observation(self):
        clean, rej, _fu = rc.split_observations([{"source": "x", "signals": ["made:up"]}],
                                                self.VOCAB, self.KINDS, self.FROUTES)
        self.assertEqual(clean, [])
        self.assertTrue(rej)

    def test_load_observations_cleans_against_real_vocab(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "reconvergence").mkdir(parents=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "pp", "signals": ["sink:dom-backlink", "param:url-fetching"],
                            "surface": [{"kind": "content", "value": "/x.xml"}]}) + "\n", encoding="utf-8")
            obs = rc.load_observations(eng)
            # the real routing vocab contains param:url-fetching but NOT sink:dom-backlink
            self.assertEqual(obs[0]["signals"], ["param:url-fetching"])
            self.assertEqual(obs[0]["surface"], [])  # `content` is rerouted (a followup), not a ledger surface

    def test_ingest_quarantines_to_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "reconvergence").mkdir(parents=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "pp", "signals": ["sink:dom-backlink"]}) + "\n", encoding="utf-8")
            rc.ingest_inbox(eng)
            sidecar = eng / "reconvergence" / "inbox.rejected.jsonl"
            self.assertTrue(sidecar.is_file())
            rec = json.loads(sidecar.read_text(encoding="utf-8").strip())
            self.assertIn("sink:dom-backlink", rec["rejected_signals"])

    def test_ingest_routes_content_to_followup_queue(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "reconvergence").mkdir(parents=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "hunt", "surface": [{"kind": "content", "value": "/sitemap.xml"}]}) + "\n",
                encoding="utf-8")
            rc.ingest_inbox(eng)
            fq = eng / "reconvergence" / "content_followups.jsonl"
            self.assertTrue(fq.is_file())
            rec = json.loads(fq.read_text(encoding="utf-8").strip())
            self.assertEqual(rec["value"], "/sitemap.xml")
            self.assertEqual(rec["route_to"], "content-discovery")
            # content was NOT quarantined as garbage
            self.assertFalse((eng / "reconvergence" / "inbox.rejected.jsonl").is_file())


class AppendWriteTimeValidator(unittest.TestCase):
    """QW-2: `--append` validates ONE record at WRITE time. A clean record is appended; a prose signal / a
    note-shaped surface / an out-of-vocab kind is REFUSED (nothing written) and -- for a note/residual --
    redirected to its real home, a coverage mark. Vocab/kinds come from the real routing map here."""
    VOCAB = {"param:url-fetching", "asset:cloud", "identity:multi"}
    KINDS = {"param", "endpoint", "identity"}
    FROUTES = {"content": "content-discovery"}

    def test_clean_record_is_appendable(self):
        rec = rc.build_record("ssrf", ["param:url-fetching"], [("endpoint", "http://10.0.0.5/")])
        res = rc.classify_append(rec, self.VOCAB, self.KINDS, self.FROUTES)
        self.assertTrue(res["ok"])
        self.assertFalse(res["rejections"])
        self.assertFalse(res["prose_signals"])

    def test_prose_signal_refused_even_fail_open(self):
        # the exact `kind:note` pollution driver: "websocket class CLEAN []" stuffed into signals. Caught
        # STRUCTURALLY, so it is refused even with an empty (unreadable) vocab where split_observations
        # would otherwise fail-open and keep it.
        rec = rc.build_record("websocket", ["websocket class CLEAN []"], [])
        res = rc.classify_append(rec, set(), set(), self.FROUTES)
        self.assertFalse(res["ok"])
        self.assertIn("websocket class CLEAN []", res["prose_signals"])

    def test_note_shaped_surface_kind_refused(self):
        rec = rc.build_record("auth", [], [("note", "RESIDUAL - not demonstrable here")])
        res = rc.classify_append(rec, self.VOCAB, self.KINDS, self.FROUTES)
        self.assertFalse(res["ok"])
        self.assertIn("note", res["note_kinds"])

    def test_out_of_vocab_typo_signal_refused(self):
        rec = rc.build_record("x", ["param:injectible"], [])  # typo of param:injectable
        res = rc.classify_append(rec, self.VOCAB, self.KINDS, self.FROUTES)
        self.assertFalse(res["ok"])
        self.assertTrue(res["rejections"])

    def test_empty_record_not_appendable(self):
        res = rc.classify_append(rc.build_record("x", [], []), self.VOCAB, self.KINDS, self.FROUTES)
        self.assertFalse(res["ok"])
        self.assertFalse(res["has_payload"])

    def test_append_observation_writes_only_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            # clean -> rc 0, one inbox line (vocab/kinds read from the real routing map).
            code, _lines = rc.append_observation(eng, "ssrf", ["param:url-fetching"],
                                                 [("endpoint", "http://10.0.0.5/")])
            self.assertEqual(code, 0)
            inbox = eng / "reconvergence" / "inbox.jsonl"
            self.assertEqual(len(inbox.read_text(encoding="utf-8").strip().splitlines()), 1)
            # prose -> rc 2, NOTHING appended (still one line), and the coverage redirect is emitted.
            code2, lines2 = rc.append_observation(eng, "websocket", ["websocket class CLEAN []"], [])
            self.assertEqual(code2, 2)
            self.assertEqual(len(inbox.read_text(encoding="utf-8").strip().splitlines()), 1)
            self.assertTrue(any("coverage.py --mark" in l for l in lines2))

    def test_append_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ok = subprocess.run(
                [sys.executable, str(SCRIPTS / "reconverge.py"), "--append", "--engagement", str(eng),
                 "--source", "ssrf", "--signal", "param:url-fetching",
                 "--surface", "endpoint=http://10.0.0.5/"], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            bad = subprocess.run(
                [sys.executable, str(SCRIPTS / "reconverge.py"), "--append", "--engagement", str(eng),
                 "--source", "auth", "--surface", "note=a residual note"], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2)


class SelfTest(unittest.TestCase):
    def test_module_selftest_passes(self):
        rc.selftest()


if __name__ == "__main__":
    unittest.main()
