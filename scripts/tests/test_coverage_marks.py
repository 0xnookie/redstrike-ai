#!/usr/bin/env python3
"""
Unit tests for the EXECUTOR-EMITTED COVERAGE MARKS feature (roadmap L-G) in scripts/coverage.py:

  * `--ingest-marks` — discover every <eng>/*/coverage_mark.json, validate each against
    coverage_mark.schema.json, and fold it into coverage_ledger.json THROUGH the existing mark() path (so
    all depth-substance / sub-surface roll-up / refusal logic still applies). A single object OR an array of
    marks per file. A malformed / schema-invalid / under-depth mark is REFUSED, never stamped.
  * `--reaffirm <CATEGORY>` — re-affirm a worked class against its ALREADY-RETAINED depth payload with NO new
    free-text note (the replacement for the copy-paste-note loop); refuses when the retained payload is
    absent/insufficient, naming the gap, instead of inventing a note.
  * coverage_mark.schema.json — validates a good mark (object or array) and rejects a malformed one, using
    the repo's own stdlib JSON-Schema subset checker (no jsonschema dependency).

Stdlib only, runnable as `python test_coverage_marks.py` (the CI convention).
"""
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
ROOT = HERE.parents[2]
sys.path.insert(0, str(SCRIPTS))

import coverage as c  # noqa: E402


def _plan(eng, signals=None):
    """Write a fresh plan ledger for `eng` (no signals -> every in-scope web category pending)."""
    m = c.load_map()
    led = c.plan(m, signals, {"web"}, eng.name)
    (eng / "coverage_ledger.json").write_text(json.dumps(led, indent=2), encoding="utf-8")
    return m


def _write_mark(eng, skill, payload):
    d = eng / skill
    d.mkdir(parents=True, exist_ok=True)
    (d / c.MARK_NAME).write_text(json.dumps(payload), encoding="utf-8")
    return d / c.MARK_NAME


def _cat(eng, cid):
    led = json.loads((eng / "coverage_ledger.json").read_text(encoding="utf-8"))
    return next(x for x in led["categories"] if x["id"] == cid)


class IngestSingleObject(unittest.TestCase):
    def test_single_object_substantiated_clear_applies(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "cors", {
                "category": "cors", "status": "attempted", "findings_count": 0, "attempts": 4,
                "variants": ["null-origin", "evil-origin"],
                "depth_note": "ACAO not reflected for arbitrary origins; ACAC never true"})
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 0)
            cors = _cat(eng, "cors")
            self.assertEqual(cors["status"], "attempted")
            self.assertTrue(cors["depth_substantiated"])
            self.assertEqual(cors["variants_tried"], ["null-origin", "evil-origin"])
            self.assertEqual(cors["attempts"], 4)

    def test_mark_file_is_left_in_place(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            mf = _write_mark(eng, "cors", {
                "category": "cors", "status": "attempted", "findings_count": 2})
            with redirect_stdout(io.StringIO()):
                c.ingest_marks(eng)
            self.assertTrue(mf.is_file(), "a successfully-ingested mark file must be left in place")

    def test_status_with_findings_needs_no_depth_payload(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "csrf", {"category": "csrf", "status": "attempted", "findings_count": 3})
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 0)
            csrf = _cat(eng, "csrf")
            self.assertEqual(csrf["findings_count"], 3)
            self.assertTrue(csrf["depth_substantiated"])


class IngestArray(unittest.TestCase):
    def test_array_of_marks_all_apply(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "wave", [
                {"category": "cors", "status": "attempted", "findings_count": 1},
                {"category": "csrf", "status": "attempted", "findings_count": 0, "attempts": 5,
                 "variants": ["token-missing", "samesite-none"], "evidence": "nb://csrf/2026-003"},
                {"category": "clickjacking", "status": "skipped", "reason": "X-Frame-Options: DENY on every route"},
            ])
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 0)
            self.assertEqual(_cat(eng, "cors")["findings_count"], 1)
            self.assertTrue(_cat(eng, "csrf")["depth_substantiated"])
            self.assertEqual(_cat(eng, "clickjacking")["status"], "skipped")

    def test_family_subsurface_mark_derives_rollup(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng, signals={"flow:auth"})
            _write_mark(eng, "auth-exec", [
                {"category": "auth", "status": "blocked", "subsurface": "oauth",
                 "reason": "oauth IdP host auth.example.com is out of scope"},
            ])
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 0)
            auth = _cat(eng, "auth")
            # one blocked leg + two un-run legs -> the family rolls up to pending (no mask).
            self.assertEqual(auth["status"], "pending")
            byleg = {s["agent"]: s["status"] for s in auth["subsurfaces"]}
            self.assertEqual(byleg["oauth"], "blocked")
            self.assertEqual(sorted(auth["pending_subsurfaces"]), ["auth-bypass", "jwt"])


class IngestRefusals(unittest.TestCase):
    def test_under_depth_attempted_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "sqli", {"category": "sqli", "status": "attempted",
                                      "findings_count": 0, "attempts": 1})
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 2)                         # a refusal makes the run non-zero
            # the flip never landed: sqli stays at its prior re-drivable status.
            sqli = _cat(eng, "sqli")
            self.assertEqual(sqli["status"], "pending")
            self.assertIn("sqli", c.redrivable_ids(
                json.loads((eng / "coverage_ledger.json").read_text()), c.load_map()))

    def test_schema_invalid_status_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "bad", {"category": "cors", "status": "not-a-status"})
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 2)
            self.assertIn("schema", buf.getvalue())
            self.assertEqual(_cat(eng, "cors")["status"], "pending")  # untouched

    def test_missing_required_category_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "bad", {"status": "attempted"})   # no `category`
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 2)

    def test_malformed_json_is_reported_not_crash(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            d = eng / "bad"
            d.mkdir()
            (d / c.MARK_NAME).write_text("{not json", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 2)
            self.assertIn("invalid JSON", buf.getvalue())

    def test_family_block_without_named_leg_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng, signals={"flow:auth"})
            _write_mark(eng, "auth-exec", {"category": "auth", "status": "blocked",
                                           "reason": "session expired"})  # names no leg
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 2)
            self.assertEqual(_cat(eng, "auth")["status"], "pending")  # never landed

    def test_no_mark_files_is_clean_noop(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 0)

    def test_no_ledger_is_rc2(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)   # no plan written
            with redirect_stdout(io.StringIO()):
                rc = c.ingest_marks(eng)
            self.assertEqual(rc, 2)


class IngestIdempotent(unittest.TestCase):
    def test_reingest_same_mark_is_stable(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            _write_mark(eng, "csrf", {"category": "csrf", "status": "attempted", "findings_count": 2,
                                      "variants": ["seq-id"]})
            with redirect_stdout(io.StringIO()):
                self.assertEqual(c.ingest_marks(eng), 0)
                self.assertEqual(c.ingest_marks(eng), 0)   # re-ingest
            csrf = _cat(eng, "csrf")
            self.assertEqual(csrf["status"], "attempted")
            self.assertEqual(csrf["findings_count"], 2)
            self.assertEqual(csrf["variants_tried"], ["seq-id"])   # merge stays de-duped


class Reaffirm(unittest.TestCase):
    def test_reaffirm_substantiated_retained_payload_succeeds(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            m = _plan(eng)
            # work the class once, recording the depth payload.
            with redirect_stdout(io.StringIO()):
                c.mark(eng, "cors", "attempted", count=0, attempts=4,
                       variants=["null-origin", "evil-origin"],
                       depth_note="ACAO not reflected for arbitrary origins; ACAC never true")
            # reaffirm with NO new note recomputes from the retained payload and succeeds.
            with redirect_stdout(io.StringIO()):
                rc = c.reaffirm(eng, "cors")
            self.assertEqual(rc, 0)
            cors = _cat(eng, "cors")
            self.assertEqual(cors["status"], "attempted")
            self.assertTrue(cors["depth_substantiated"])

    def test_reaffirm_promotes_pending_with_retained_findings(self):
        # a to-be-attempted (pending) category with >=1 retained finding is self-evidently substantiated.
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            cors = _cat(eng, "cors")
            self.assertEqual(cors["status"], "pending")
            # inject a retained finding count without flipping status (simulates a prior count reconcile).
            led = json.loads((eng / "coverage_ledger.json").read_text())
            next(x for x in led["categories"] if x["id"] == "cors")["findings_count"] = 1
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                rc = c.reaffirm(eng, "cors")
            self.assertEqual(rc, 0)
            self.assertEqual(_cat(eng, "cors")["status"], "attempted")

    def test_reaffirm_insufficient_retained_payload_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = c.reaffirm(eng, "cors")   # bare pending, no retained depth
            self.assertEqual(rc, 2)
            self.assertIn("does not substantiate", buf.getvalue())
            self.assertNotIn("invent", buf.getvalue().split("does not substantiate")[0])
            self.assertEqual(_cat(eng, "cors")["status"], "pending")  # untouched, stays re-drivable

    def test_reaffirm_unknown_category_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.reaffirm(eng, "does-not-exist")
            self.assertEqual(rc, 2)

    def test_reaffirm_no_ledger_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            with redirect_stdout(io.StringIO()):
                rc = c.reaffirm(pathlib.Path(t), "cors")
            self.assertEqual(rc, 2)

    def test_reaffirm_family_with_uncovered_leg_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng, signals={"flow:auth"})
            # mark only one leg attempted; the others stay pending -> the family must not reaffirm.
            with redirect_stdout(io.StringIO()):
                c.mark(eng, "auth", "attempted", subsurface="jwt", count=1, note="jwt forgery confirmed")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = c.reaffirm(eng, "auth")
            self.assertEqual(rc, 2)
            self.assertIn("not", buf.getvalue())
            self.assertEqual(_cat(eng, "auth")["status"], "pending")

    def test_reaffirm_subsurface_leg_rederives_rollup(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng, signals={"flow:auth"})
            with redirect_stdout(io.StringIO()):
                c.mark(eng, "auth", "attempted", subsurface="jwt", count=1, note="jwt forgery confirmed")
                rc = c.reaffirm(eng, "auth", subsurface="jwt")
            self.assertEqual(rc, 0)
            byleg = {s["agent"]: s["status"] for s in _cat(eng, "auth")["subsurfaces"]}
            self.assertEqual(byleg["jwt"], "attempted")

    def test_reaffirm_subsurface_on_nonfamily_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng)
            with redirect_stdout(io.StringIO()):
                rc = c.reaffirm(eng, "secrets", subsurface="x")
            self.assertEqual(rc, 2)

    def test_reaffirm_subsurface_unmarked_leg_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            eng = pathlib.Path(t)
            _plan(eng, signals={"flow:auth"})
            with redirect_stdout(io.StringIO()):
                rc = c.reaffirm(eng, "auth", subsurface="jwt")   # never marked
            self.assertEqual(rc, 2)


class MarkSchema(unittest.TestCase):
    """coverage_mark.schema.json validates a good mark (object or array) and rejects a malformed one — via
    the repo's stdlib JSON-Schema subset checker (stdlib only, no jsonschema dependency)."""

    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((ROOT / "skills" / "_contract" / "coverage_mark.schema.json")
                                .read_text(encoding="utf-8"))
        vp = ROOT / "skills" / "_contract" / "verify_completion.py"
        spec = importlib.util.spec_from_file_location("vc_for_mark_schema_test", vp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.vc = mod

    def _errors(self, obj):
        # validate against the whole schema (the top-level object-or-array anyOf).
        return self.vc._stdlib_schema_errors(obj, self.schema, root=self.schema)

    def test_good_single_object_passes(self):
        self.assertEqual(self._errors(
            {"category": "sqli", "status": "attempted", "findings_count": 0, "attempts": 6,
             "variants": ["a", "b"], "depth_note": "x" * 30}), [])

    def test_good_array_passes(self):
        self.assertEqual(self._errors([
            {"category": "cors", "status": "attempted", "findings_count": 1},
            {"category": "auth", "status": "blocked", "subsurface": "oauth", "reason": "OOS"}]), [])

    def test_blocked_family_mark_shape_passes(self):
        self.assertEqual(self._errors(
            {"category": "auth", "status": "blocked", "blocked_subsurfaces": ["oauth"],
             "reason": "oauth leg OOS"}), [])

    def test_bad_status_enum_rejected(self):
        self.assertTrue(self._errors({"category": "sqli", "status": "bogus"}))

    def test_missing_required_field_rejected(self):
        self.assertTrue(self._errors({"status": "attempted"}))          # no category
        self.assertTrue(self._errors({"category": "sqli"}))             # no status

    def test_unexpected_property_rejected(self):
        self.assertTrue(self._errors({"category": "sqli", "status": "attempted", "surprise": 1}))

    def test_negative_count_rejected(self):
        self.assertTrue(self._errors({"category": "sqli", "status": "attempted", "findings_count": -1}))

    def test_empty_array_rejected(self):
        # minItems:1 — an empty mark file is meaningless.
        self.assertTrue(self._errors([]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
