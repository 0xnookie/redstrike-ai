#!/usr/bin/env python3
"""
E3 — positive + branch coverage for the mechanical completion gate.

Before this file CI only exercised ONE branch of verify_completion.py: an empty
output dir against the reflected-XSS manifest => exit 2 (the negative path, in
.github/workflows/validate.yml). Nothing proved a WELL-FORMED engagement PASSES,
nothing exercised the stdlib schema validator (T1), the multi-layout finding
discovery (OPT-2), or the per-artifact checks. This fills that in.

Stdlib only, runnable as `python test_verify_completion.py` (the CI convention —
see cli/tests/). It imports the real module and uses the REAL finding.schema.json,
so a finding that passes here passes the gate the orchestrator actually runs.
"""
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).resolve()
CONTRACT = HERE.parents[1]                 # skills/_contract
REPO = HERE.parents[3]                     # repo root
sys.path.insert(0, str(CONTRACT))
sys.path.insert(0, str(REPO / "scripts"))

import verify_completion as vc  # noqa: E402
import model_ledger as ml  # noqa: E402 — the cross-model dispatch ledger the diversity check reads


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def valid_finding(**over) -> dict:
    """A finding that conforms to the real finding.schema.json. Override fields
    via kwargs to build the negative cases."""
    f = {
        "id": "RS-2026-001",
        "title": "Reflected XSS in the search parameter",
        "asset": "https://app.acme.com/search",
        "category": {"owasp": "A03:2021-Injection", "cwe": "CWE-79"},
        "severity": "high",
        "confidence": "confirmed",
        "status": "verified",
        "evidence": [{"type": "request_response", "ref": "findings/evidence/xss-1.txt"}],
        "reproduction": ["Send `GET /search?q=<svg/onload=alert(1)>`", "Observe script execution"],
        "review": {"verdict": "accepted", "reviewer": "xss-reflected-verify",
                   "scope_ok": True, "rubric": {"reflection_vs_execution": "pass"}},
        # Cross-model SECOND verdict (R3): the model-pinned adversarial-verify reviewer re-ran the base
        # checks on a DIFFERENT model than the executor/primary reviewer and confirmed the finding. Required
        # (gated) for an accepted High/Critical finding or any chain once a report exists.
        "secondary_review": {"verdict": "accepted", "reviewer": "adversarial-verify",
                             "scope_ok": True,
                             "method": "cross-model re-run on a different model than the executor/primary "
                                       "reviewer (shared-model hallucination guard)",
                             "rubric": {"reflection_vs_execution": "pass"}},
    }
    f.update(over)
    return f


def write_evidence(eng: pathlib.Path, finding: dict) -> None:
    for item in finding.get("evidence", []):
        ref = (item or {}).get("ref")
        if ref:
            p = eng / ref
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("GET /search?q=<svg/onload=alert(1)>\n\nHTTP/1.1 200 OK\n<svg/onload=alert(1)>\n",
                         encoding="utf-8")


def substantiate_attempted(led: dict) -> dict:
    """Give every zero-finding `attempted` category in a coverage ledger the depth evidence the coverage
    gate's depth-substance bar requires, i.e. model a legitimately deeply-probed-but-empty clear (not a
    rubber-stamped `--mark attempted --count 0`). Each such category gets enough distinct probe ATTEMPTS and
    technique VARIANTS for the strictest per-class threshold (sqli/xss: 5 attempts / 2 variants) PLUS a
    differential note of real length. A category with findings, or already `blocked`/`skipped`/`pending`, is
    left untouched. Idempotent; mutates + returns ``led``. Mirrors how an executor records its own depth
    (variants_tried / depth_note), so the fixtures represent a real complete engagement, not a gate dodge."""
    for c in led.get("categories", []):
        if not isinstance(c, dict):
            continue
        if str(c.get("status")) == "attempted" and not (c.get("findings_count") or 0):
            c["attempts"] = max(int(c.get("attempts") or 0), 6)
            c["variants_tried"] = sorted(
                set(c.get("variants_tried") or [])
                | {"baseline-probe", "encoding-evasion", "nested-context", "filter-bypass"})
            if not (str(c.get("depth_note") or "").strip() or str(c.get("differential") or "").strip()):
                c["depth_note"] = ("probed with baseline, encoded, nested and filter-evasion payloads; "
                                   "every response matched the benign control (no differential)")
    return led


def write_exhaustion_review(eng: pathlib.Path, *, verdict="no_gaps_found", gaps=None, model="sonnet") -> None:
    """Write a passing cross-model exhaustion-adversary verdict to runtime/exhaustion_review.json so a
    report-present fixture satisfies the exhaustion-adversary HARD gate WITHOUT weakening it. A complete,
    report-ready engagement must carry this artifact exactly as it must carry a per-finding secondary_review
    — the cross-model adversary ran and could not disprove 'engagement complete'. Mirrors how the executor
    records its own depth (substantiate_attempted): the fixtures model a real complete engagement, not a
    gate dodge. Pass verdict='found_gaps' / explicit gaps to build the NEGATIVE cases; pass `model=` to drive
    the model-diversity self-report cross-check (the SELF-REPORTED model vs the model ledger)."""
    (eng / "runtime").mkdir(parents=True, exist_ok=True)
    doc = {"version": 1, "verdict": verdict, "model": model, "reviewer": "exhaustion-adversary",
           "reviewed_at": "2026-01-01T02:00:00Z",
           "checked": ["coverage_ledger", "surface_ledger", "findings", "recall_audit", "audit_trail"],
           "gaps": gaps if gaps is not None else []}
    (eng / "runtime" / "exhaustion_review.json").write_text(json.dumps(doc), encoding="utf-8")


SCOPE_YAML = """engagement: "acme-2026"
authorized_by: sec@acme / auth-1
in_scope:
  domains:
    - "*.acme.com"
  cidrs: []
  urls:
    - "https://app.acme.com"
out_of_scope:
  domains: []
  cidrs: []
rules:
  no_dos: true
"""


# --------------------------------------------------------------------------- #
# the stdlib JSON-Schema subset validator (T1)
# --------------------------------------------------------------------------- #
class TestStdlibSchemaValidator(unittest.TestCase):
    def E(self, data, schema, **kw):
        return vc._stdlib_schema_errors(data, schema, **kw)

    def test_enum(self):
        s = {"enum": ["a", "b"]}
        self.assertEqual(self.E("a", s), [])
        self.assertTrue(self.E("z", s))

    def test_pattern_and_length(self):
        s = {"type": "string", "pattern": r"^RS-[0-9]{4}$", "minLength": 2, "maxLength": 7}
        self.assertEqual(self.E("RS-2026", s), [])          # 7 chars, matches
        self.assertTrue(self.E("nope", s))                  # pattern miss
        self.assertEqual(self.E("abc", {"type": "string", "maxLength": 7}), [])   # within max
        self.assertTrue(self.E("abcdefgh", {"type": "string", "maxLength": 7}))   # over max
        self.assertTrue(self.E("a", {"type": "string", "minLength": 2}))          # under min

    def test_numeric_bounds(self):
        s = {"type": "number", "minimum": 0, "maximum": 10}
        self.assertEqual(self.E(5, s), [])
        self.assertTrue(self.E(-1, s))
        self.assertTrue(self.E(11, s))
        # bool must not be treated as a number
        self.assertEqual(self.E(True, {"type": "number", "minimum": 5}), [])

    def test_required_and_additional_properties(self):
        s = {"type": "object", "required": ["a"], "additionalProperties": False,
             "properties": {"a": {"type": "string"}}}
        self.assertEqual(self.E({"a": "x"}, s), [])
        self.assertTrue(any("missing required 'a'" in e for e in self.E({}, s)))
        self.assertTrue(any("unexpected property 'b'" in e for e in self.E({"a": "x", "b": 1}, s)))

    def test_additional_properties_subschema(self):
        # review.rubric shape: free keys, each value constrained to an enum
        s = {"type": "object", "additionalProperties": {"enum": ["pass", "fail", "n/a"]}}
        self.assertEqual(self.E({"any_check": "pass"}, s), [])
        self.assertTrue(self.E({"any_check": "weak"}, s))

    def test_array_items_and_bounds(self):
        # per-item constraint the schemas actually use: an enum on each element
        s = {"type": "array", "minItems": 1, "maxItems": 2, "items": {"enum": ["x", "y"]}}
        self.assertEqual(self.E(["x"], s), [])
        self.assertTrue(self.E([], s))                      # minItems
        self.assertTrue(self.E(["x", "y", "x"], s))         # maxItems
        self.assertTrue(self.E(["z"], s))                   # item off the enum
        # type:array itself IS enforced (unlike scalar types — see below)
        self.assertTrue(self.E("notalist", {"type": "array"}))

    def test_ref_and_anyof(self):
        root = {"$defs": {"sev": {"enum": ["high", "low"]}}}
        self.assertEqual(self.E("high", {"$ref": "#/$defs/sev"}, root=root), [])
        self.assertTrue(self.E("mid", {"$ref": "#/$defs/sev"}, root=root))
        # anyOf across the container types the validator enforces
        any_s = {"anyOf": [{"type": "array"}, {"type": "object"}]}
        self.assertEqual(self.E([], any_s), [])
        self.assertEqual(self.E({}, any_s), [])
        self.assertTrue(self.E("neither", any_s))

    def test_scalar_type_not_enforced_known_limitation(self):
        """DOCUMENTED limitation of the dependency-free validator: a bare scalar
        `type` (string/number/integer/boolean) is NOT asserted on its own — the
        Redstrike schemas constrain scalars with enum/pattern/min-max instead, and
        jsonschema (when installed) still enforces type. If this ever gains scalar
        type-checking, flip this test deliberately."""
        self.assertEqual(self.E(123, {"type": "string", "minLength": 4}), [])
        self.assertEqual(self.E("x", {"type": "number", "minimum": 0}), [])


# --------------------------------------------------------------------------- #
# per-artifact checks (the --skill / per-skill mode)
# --------------------------------------------------------------------------- #
class TestCheckArtifact(unittest.TestCase):
    def _out(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def test_text_file(self):
        out = self._out()
        (out / "recon").mkdir()
        (out / "recon" / "notes.txt").write_text("hello", encoding="utf-8")
        ok, _ = vc.check_artifact({"type": "text", "path": "recon/notes.txt"}, out)
        self.assertTrue(ok)
        ok, note = vc.check_artifact({"type": "text", "path": "recon/missing.txt"}, out)
        self.assertFalse(ok)
        self.assertIn("missing file", note)

    def test_min_bytes_and_must_contain(self):
        out = self._out()
        (out / "a.txt").write_text("tiny", encoding="utf-8")
        ok, _ = vc.check_artifact({"type": "text", "path": "a.txt", "min_bytes": 100}, out)
        self.assertFalse(ok)
        (out / "b.txt").write_text("the TOKEN is here", encoding="utf-8")
        self.assertTrue(vc.check_artifact({"type": "text", "path": "b.txt", "must_contain": "TOKEN"}, out)[0])
        self.assertFalse(vc.check_artifact({"type": "text", "path": "b.txt", "must_contain": "ABSENT"}, out)[0])

    def test_json_artifact(self):
        out = self._out()
        (out / "ok.json").write_text(json.dumps({"a": 1}), encoding="utf-8")
        self.assertTrue(vc.check_artifact({"type": "json", "path": "ok.json"}, out)[0])
        (out / "bad.json").write_text("{not json", encoding="utf-8")
        self.assertFalse(vc.check_artifact({"type": "json", "path": "bad.json"}, out)[0])
        (out / "empty.json").write_text("[]", encoding="utf-8")
        self.assertFalse(vc.check_artifact({"type": "json", "path": "empty.json"}, out)[0])
        self.assertTrue(vc.check_artifact(
            {"type": "json", "path": "empty.json", "allow_empty_array": True}, out)[0])

    def test_jsonl_artifact(self):
        out = self._out()
        (out / "rows.jsonl").write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
        self.assertTrue(vc.check_artifact({"type": "jsonl", "path": "rows.jsonl"}, out)[0])
        (out / "empty.jsonl").write_text("", encoding="utf-8")
        self.assertFalse(vc.check_artifact({"type": "jsonl", "path": "empty.jsonl"}, out)[0])
        self.assertTrue(vc.check_artifact(
            {"type": "jsonl", "path": "empty.jsonl", "allow_empty": True}, out)[0])

    def test_glob_and_dir(self):
        out = self._out()
        shots = out / "shots"
        shots.mkdir()
        (shots / "1.png").write_text("x", encoding="utf-8")
        (shots / "2.png").write_text("y", encoding="utf-8")
        self.assertTrue(vc.check_artifact(
            {"type": "glob", "path": "shots/*.png", "min_matches": 2}, out)[0])
        self.assertFalse(vc.check_artifact(
            {"type": "glob", "path": "shots/*.png", "min_matches": 3}, out)[0])
        self.assertTrue(vc.check_artifact({"type": "dir", "path": "shots", "min_children": 2}, out)[0])
        self.assertFalse(vc.check_artifact({"type": "dir", "path": "shots", "min_children": 5}, out)[0])
        self.assertFalse(vc.check_artifact({"type": "dir", "path": "nope"}, out)[0])


# --------------------------------------------------------------------------- #
# manifest loading
# --------------------------------------------------------------------------- #
class TestLoadManifest(unittest.TestCase):
    def test_picks_first_artifacts_object(self):
        with tempfile.TemporaryDirectory() as d:
            rp = pathlib.Path(d) / "review.md"
            rp.write_text(
                "# review\n\n"
                "```json\n{\"not_a_manifest\": true}\n```\n\n"      # skipped: no 'artifacts'
                "```json\n{\"skill\": \"demo\", \"artifacts\": "
                "[{\"id\": \"a\", \"path\": \"a.txt\"}]}\n```\n",
                encoding="utf-8")
            m = vc.load_manifest(rp)
            self.assertEqual(m["skill"], "demo")
            self.assertEqual(m["artifacts"][0]["path"], "a.txt")

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            vc.load_manifest(pathlib.Path("/no/such/review.md"))


# --------------------------------------------------------------------------- #
# finding discovery across layouts (OPT-2)
# --------------------------------------------------------------------------- #
class TestFindingDiscovery(unittest.TestCase):
    def test_load_findings_array_shapes(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "arr.json").write_text(json.dumps([{"id": "RS-2026-001"}]), encoding="utf-8")
            self.assertEqual(len(vc._load_findings_array(d / "arr.json")), 1)
            (d / "rep.json").write_text(json.dumps(
                {"findings": [{"id": "a"}], "attack_chains": [{"id": "c"}]}), encoding="utf-8")
            self.assertEqual(len(vc._load_findings_array(d / "rep.json")), 2)
            (d / "bad.json").write_text("{nope", encoding="utf-8")
            self.assertIsNone(vc._load_findings_array(d / "bad.json"))

    def test_discover_root_layout(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "findings.json").write_text(json.dumps([valid_finding()]), encoding="utf-8")
            findings, src = vc._discover_engagement_findings(eng)
            self.assertEqual(len(findings), 1)
            self.assertEqual(src, "findings.json")

    def test_discover_per_skill_union(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            for skill, fid in (("xss-reflected", "RS-2026-001"), ("sqli-inband", "RS-2026-002")):
                (eng / skill).mkdir()
                (eng / skill / "findings.json").write_text(
                    json.dumps([valid_finding(id=fid)]), encoding="utf-8")
            findings, src = vc._discover_engagement_findings(eng)
            self.assertEqual({f["id"] for f in findings}, {"RS-2026-001", "RS-2026-002"})
            self.assertIn("per-skill", src)

    def test_discover_consolidated(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "report").mkdir()
            (eng / "report" / "findings_consolidated.json").write_text(
                json.dumps({"findings": [valid_finding()], "attack_chains": []}), encoding="utf-8")
            findings, src = vc._discover_engagement_findings(eng)
            self.assertEqual(len(findings), 1)
            self.assertIn("consolidated", src)

    def test_discover_none(self):
        with tempfile.TemporaryDirectory() as d:
            findings, reason = vc._discover_engagement_findings(pathlib.Path(d))
            self.assertIsNone(findings)
            self.assertIn("no findings.json", reason)

    def test_collect_verdict_ids(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "reviews").mkdir()
            (eng / "reviews" / "RS-2026-001.verdict.json").write_text("{}", encoding="utf-8")
            (eng / "xss" / "reviews").mkdir(parents=True)
            (eng / "xss" / "reviews" / "RS-2026-002.verdict.json").write_text("{}", encoding="utf-8")
            self.assertEqual(vc._collect_verdict_ids(eng), {"RS-2026-001", "RS-2026-002"})


# --------------------------------------------------------------------------- #
# single-finding hard/soft checks (uses the REAL schema)
# --------------------------------------------------------------------------- #
class TestCheckFinding(unittest.TestCase):
    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def test_valid_finding_passes(self):
        eng = self._eng()
        f = valid_finding()
        write_evidence(eng, f)
        ok, detail, warns = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok, detail)
        self.assertNotIn("severity", "".join(warns))  # no drift warning (no cvss_mod)

    def test_missing_required_field_fails(self):
        eng = self._eng()
        f = valid_finding()
        del f["reproduction"]
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("reproduction", detail)

    def test_missing_evidence_file_fails(self):
        eng = self._eng()
        f = valid_finding()  # evidence ref not written to disk
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("ref not found", detail)

    def test_schema_violation_bad_enum_fails(self):
        eng = self._eng()
        f = valid_finding(severity="sev-high")   # not in the severity enum
        write_evidence(eng, f)
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("schema violation", detail)

    def test_schema_violation_stray_key_fails(self):
        eng = self._eng()
        f = valid_finding(surprise="extra")       # additionalProperties:false
        write_evidence(eng, f)
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("schema violation", detail)

    def test_review_block_bad_rubric_enum_fails(self):
        # the exact A1 defect class: a reviewer-written rubric value off the enum
        eng = self._eng()
        f = valid_finding()
        f["review"]["rubric"] = {"fp_gauntlet": "weak"}  # must be pass|fail|n/a
        write_evidence(eng, f)
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("schema violation", detail)

    def test_out_of_scope_asset_warns_not_fails(self):
        eng = self._eng()
        f = valid_finding(asset="https://evil.example.org/x")
        write_evidence(eng, f)
        ok, _detail, warns = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok)  # soft
        self.assertTrue(any("not found in scope" in w for w in warns))

    def test_reviewed_without_verdict_warns(self):
        eng = self._eng()
        f = valid_finding(status="verified")
        del f["review"]                      # verified but no review + no verdict file
        write_evidence(eng, f)
        ok, _d, warns = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok)
        self.assertTrue(any("no review block" in w for w in warns))


# --------------------------------------------------------------------------- #
# the headline: a well-formed engagement PASSES (in-process + exit-code contract)
# --------------------------------------------------------------------------- #
class TestValidateEngagementE2E(unittest.TestCase):
    def _good_engagement(self, d) -> pathlib.Path:
        eng = pathlib.Path(d)
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        f = valid_finding()
        write_evidence(eng, f)
        (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
        return eng

    def test_good_engagement_passes_text(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._good_engagement(d)
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=False)
            out = buf.getvalue()
            self.assertTrue(ok, out)
            self.assertIn("PASS", out)
            self.assertIn("RS-2026-001", out)

    def test_good_engagement_passes_json(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._good_engagement(d)
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            self.assertTrue(ok)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["pass"])
            self.assertEqual(payload["failed"], 0)
            self.assertEqual(payload["findings_checked"], 1)

    def test_bad_engagement_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()  # evidence file deliberately not written
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=False)
            self.assertFalse(ok)
            self.assertIn("FAIL", buf.getvalue())

    def test_exit_code_contract_via_subprocess(self):
        """Orchestrators treat exit 0 = complete, exit 2 = re-run. Lock BOTH ends
        (CI only had the exit-2 empty-dir case)."""
        script = CONTRACT / "verify_completion.py"
        with tempfile.TemporaryDirectory() as d:
            eng = self._good_engagement(d)
            good = subprocess.run([sys.executable, str(script), "--engagement", str(eng)],
                                  capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "findings.json").write_text(json.dumps([valid_finding()]), encoding="utf-8")
            bad = subprocess.run([sys.executable, str(script), "--engagement", str(eng)],
                                 capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2, bad.stdout + bad.stderr)


# --------------------------------------------------------------------------- #
# Fix #2: coverage is a HARD gate once a report exists (no report over silent gaps)
# --------------------------------------------------------------------------- #
class TestCoverageHardGate(unittest.TestCase):
    """While hunting, coverage gaps are warnings. But once report/findings_consolidated.json
    exists the engagement claims DONE — a missing ledger or any `pending` category must then
    FAIL the gate (the juice-shop-2026-10-20 failure: whole classes never ran, clean report)."""

    def _cov(self):
        cov = vc._try_import_coverage()
        self.assertIsNotNone(cov, "scripts/coverage.py must import for this test")
        return cov

    def _ledger(self, cov, *, all_terminal: bool):
        """A plan for web phase; optionally flip every routed `pending` to a terminal status so
        the ledger is 'complete'. Leaving one `pending` models an un-run routed class."""
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if all_terminal and c["status"] == "pending":
                c["status"] = "attempted"
                c["findings_count"] = 0
        # a 'complete' ledger's zero-finding clears must be depth-substantiated (a no-op when nothing flipped)
        return substantiate_attempted(led)

    def _surface_ledger(self):
        """A non-empty surface ledger with every routed surface marked `tested`, so the
        report-time strict surface gate (_surface_hard_errors) passes. Mirrors `_ledger`
        for coverage: the happy-path engagement must satisfy EVERY hard gate, and surface
        coverage became a hard gate at report time after this test was first written."""
        sf = vc._try_import_surface()
        self.assertIsNotNone(sf, "scripts/surface.py must import for this test")
        led = sf.plan_from_items("acme-2026", [
            {"kind": "endpoint", "value": "/api/login", "discovered_by": "recon"},
            {"kind": "param", "value": "id", "discovered_by": "recon"},
        ])
        for s in led["surfaces"]:
            if s["status"] == "discovered":  # discovered-but-untested is the gap the gate catches
                s["status"] = "tested"
        return led

    def _write_report(self, eng):
        f = valid_finding()
        (eng / "report").mkdir(parents=True, exist_ok=True)
        # evidence refs resolve from the engagement root
        for item in f.get("evidence", []):
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)

    def test_report_with_pending_category_fails(self):
        cov = self._cov()
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._write_report(eng)
            (eng / "coverage_ledger.json").write_text(
                json.dumps(self._ledger(cov, all_terminal=False)), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=False)
            self.assertFalse(ok, buf.getvalue())
            self.assertIn("coverage gate", buf.getvalue())

    def test_report_with_missing_ledger_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._write_report(eng)  # no coverage_ledger.json at all
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertFalse(payload["pass"])
            self.assertTrue(payload["coverage_errors"])

    def test_report_with_complete_ledger_passes(self):
        cov = self._cov()
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._write_report(eng)
            (eng / "coverage_ledger.json").write_text(
                json.dumps(self._ledger(cov, all_terminal=True)), encoding="utf-8")
            # the happy path must satisfy the surface hard gate too, not only coverage
            (eng / "surface_ledger.json").write_text(
                json.dumps(self._surface_ledger()), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=False)
            self.assertTrue(ok, buf.getvalue())

    def test_no_report_pending_is_warning_not_failure(self):
        """Mid-hunt (no consolidated report): a pending ledger must NOT fail the gate."""
        cov = self._cov()
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()
            write_evidence(eng, f)
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            (eng / "coverage_ledger.json").write_text(
                json.dumps(self._ledger(cov, all_terminal=False)), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["pass"], buf.getvalue())
            self.assertFalse(payload["coverage_errors"])
            self.assertTrue(any("coverage" in w for w in payload["warnings"]))


# --------------------------------------------------------------------------- #
# Duplicate finding-id gate: ids must be engagement-unique once a report exists
# --------------------------------------------------------------------------- #
class TestDuplicateIdGate(unittest.TestCase):
    def _with_report(self, eng):
        (eng / "report").mkdir(parents=True, exist_ok=True)
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": []}), encoding="utf-8")

    def test_helper_silent_without_report(self):
        """Mid-hunt (no consolidated report): duplicate ids must NOT fail — behavior unchanged."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self.assertEqual(vc._duplicate_id_errors(eng, [valid_finding(), valid_finding()]), [])

    def test_helper_flags_duplicate_with_report(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._with_report(eng)
            errs = vc._duplicate_id_errors(eng, [valid_finding(), valid_finding()])
            self.assertTrue(errs)
            self.assertIn("RS-2026-001", errs[0])

    def test_helper_unique_ids_ok_with_report(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._with_report(eng)
            errs = vc._duplicate_id_errors(
                eng, [valid_finding(), valid_finding(id="RS-2026-002")])
            self.assertEqual(errs, [])

    def test_validate_engagement_flags_duplicate_across_skills(self):
        """Two per-skill findings.json emitting the same id, a report present => HARD fail."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f1, f2 = valid_finding(), valid_finding()  # same default id
            write_evidence(eng, f1)
            (eng / "a").mkdir(); (eng / "b").mkdir()
            (eng / "a" / "findings.json").write_text(json.dumps([f1]), encoding="utf-8")
            (eng / "b" / "findings.json").write_text(json.dumps([f2]), encoding="utf-8")
            self._with_report(eng)
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertFalse(payload["pass"], buf.getvalue())
            self.assertTrue(payload["duplicate_id_errors"])


# --------------------------------------------------------------------------- #
# E4: cve_intel schema reconciliation (cves|entries drift) + manifest wiring
# --------------------------------------------------------------------------- #
class TestCveIntelSchema(unittest.TestCase):
    """The reconciled cve_intel.schema.json accepts BOTH the canonical `cves` key
    and the `entries` alias (the console reads either), enforces the per-CVE item
    shape, and rejects the old per-component shape the real run had drifted to."""
    SCHEMA = "skills/_contract/cve_intel.schema.json"

    def ok(self, doc):
        return vc._validate_against_schema(doc, self.SCHEMA)[0]

    def _base(self, **extra):
        d = {"target": "https://app.acme.com", "generated_at": "2026-01-01T00:00:00Z"}
        d.update(extra)
        return d

    def test_accepts_cves_and_entries_keys(self):
        row = {"component": "jquery", "version": "3.4.1", "cve": "CVE-2020-11022"}
        self.assertTrue(self.ok(self._base(cves=[row])))
        self.assertTrue(self.ok(self._base(entries=[row])))

    def test_empty_result_is_valid(self):
        # cve-intelligence finding nothing is a PASS — neither key required
        self.assertTrue(self.ok(self._base()))

    def test_rich_per_cve_row_passes(self):
        row = {"component": "nginx", "cve": "CVE-2021-23017", "cvss": "7.7",
               "reachable": "yes", "confidence": "probable", "kev": True,
               "epss": 0.42, "priority_rank": 1, "source": ["nvd", "osv"]}
        self.assertTrue(self.ok(self._base(cves=[row])))

    def test_item_missing_required_cve_fails(self):
        self.assertFalse(self.ok(self._base(cves=[{"component": "jquery"}])))

    def test_old_per_component_shape_fails(self):
        # {component, cves:[...], applies, exploited} — the drifted shape
        bad = {"component": "jquery", "cves": ["CVE-2020-11022"], "applies": "yes", "exploited": False}
        self.assertFalse(self.ok(self._base(entries=[bad])))

    def test_unknown_top_level_key_fails(self):
        self.assertFalse(self.ok(self._base(cves=[], bogus=1)))

    def test_bad_cve_pattern_fails(self):
        self.assertFalse(self.ok(self._base(cves=[{"component": "x", "cve": "not-a-cve"}])))


class TestManifestSchemaRefs(unittest.TestCase):
    """E4 wiring guard (mirrors validate.py as a fast unit test in the same CI step):
    every `schema` a manifest declares must resolve to a real _contract schema, else
    check_artifact silently skips validation. Also pins that the wiring is present."""
    def test_every_wired_schema_ref_resolves(self):
        import glob
        refs = 0
        for rv in sorted(glob.glob(str(REPO / "skills" / "*" / "review.md"))):
            text = pathlib.Path(rv).read_text(encoding="utf-8")
            for m in vc.FENCE_RE.finditer(text):
                try:
                    obj = json.loads(m.group(1))
                except json.JSONDecodeError:
                    continue
                if not (isinstance(obj, dict) and "artifacts" in obj):
                    continue
                for a in obj["artifacts"]:
                    ref = a.get("schema")
                    if not ref:
                        continue
                    refs += 1
                    self.assertTrue(
                        isinstance(ref, str) and ref.startswith("skills/_contract/")
                        and ref.endswith(".schema.json"), f"{rv}: odd schema ref {ref!r}")
                    self.assertTrue((REPO / ref).is_file(), f"{rv}: dangling schema ref {ref}")
        # 79 findings.json + 14 *_context.json + cve_intel.json + pre-existing attack_chain
        self.assertGreaterEqual(refs, 94, "expected the finding/context/cve_intel schema wiring to be present")


class TestSchemaVersioning(unittest.TestCase):
    """P2-3: finding / attack_chain / *_context schemas declare an optional `version` field so artifacts
    can be stamped and evolve. It is optional (backward-compatible) and an integer when present."""

    def test_finding_accepts_version_and_without(self):
        eng = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(eng, ignore_errors=True))
        # with a version stamp
        f = valid_finding(version=1)
        write_evidence(eng, f)
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok, detail)
        # and without one (optional / backward-compatible)
        f2 = valid_finding()
        write_evidence(eng, f2)
        ok2, detail2, _ = vc.check_finding(f2, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok2, detail2)

    def test_context_schemas_accept_version(self):
        base = {"target": "https://app.acme.com", "generated_at": "2026-01-01T00:00:00Z", "version": 1,
                "injection_points": [{"id": "sq-001", "endpoint": "/q", "param": "q"}]}
        self.assertTrue(vc._validate_against_schema(base, "skills/_contract/sqli_context.schema.json")[0])

    def test_attack_chain_accepts_version(self):
        doc = {"version": 1, "target": "x", "generated_at": "2026-01-01T00:00:00Z",
               "chains": [{"id": "chain-001", "title": "t",
                           "steps": [{"finding_id": "RS-2026-001", "role": "entry"},
                                     {"finding_id": "RS-2026-002", "role": "exfil"}]}]}
        self.assertTrue(vc._validate_against_schema(doc, "skills/_contract/attack_chain.schema.json")[0])

    def test_all_target_schemas_declare_version(self):
        import glob
        for scm in sorted(glob.glob(str(REPO / "skills/_contract/*_context.schema.json"))):
            d = json.loads(pathlib.Path(scm).read_text(encoding="utf-8"))
            self.assertIn("version", d.get("properties", {}), scm)
        ac = json.loads((REPO / "skills/_contract/attack_chain.schema.json").read_text(encoding="utf-8"))
        self.assertIn("version", ac["properties"])
        fd = json.loads((REPO / "skills/_contract/finding.schema.json").read_text(encoding="utf-8"))
        self.assertIn("version", fd["$defs"]["finding"]["properties"])


class TestContextSchemas(unittest.TestCase):
    """E4 context wiring: the *_context schemas are the canonical output contract
    (each producer's SKILL.md says its output 'validates against the schema'), so a
    conformant instance passes and the shapes real runs drifted to are rejected —
    which is why wiring the schema into the manifest is the fix, not a schema change."""
    B = {"target": "https://app.acme.com", "generated_at": "2026-01-01T00:00:00Z"}

    def ok(self, doc, schema):
        return vc._validate_against_schema(doc, f"skills/_contract/{schema}")[0]

    def test_injection_and_sqli_style_conformant_passes(self):
        self.assertTrue(self.ok(
            {**self.B, "injection_points": [{"id": "inj-001", "endpoint": "/q", "param": "q"}]},
            "injection_context.schema.json"))
        self.assertTrue(self.ok(
            {**self.B, "injection_points": [{"id": "sq-001", "endpoint": "/q", "param": "q"}]},
            "sqli_context.schema.json"))

    def test_authz_conformant_passes_drifted_fails(self):
        self.assertTrue(self.ok(
            {**self.B, "identities": [{"label": "low", "role": "user"}]},
            "authz_context.schema.json"))
        # the real drift: identities[].id/.auth instead of .label/.role
        self.assertFalse(self.ok(
            {**self.B, "identities": [{"id": "u1", "auth": "cookie"}]},
            "authz_context.schema.json"))

    def test_xss_conformant_passes_drifted_fails(self):
        conformant = {**self.B, "csp": {"present": False}, "dom": {},
                      "injection_points": [{"id": "ip-001", "endpoint": "/s", "method": "GET",
                                            "source": "query", "reflects": True}]}
        self.assertTrue(self.ok(conformant, "xss_context.schema.json"))
        # the real drift: id 'xc-001' (wrong prefix) + 'type', missing source/reflects
        drifted = {**self.B, "csp": {"present": False}, "dom": {},
                   "injection_points": [{"id": "xc-001", "type": "reflected",
                                         "endpoint": "/s", "method": "GET"}]}
        self.assertFalse(self.ok(drifted, "xss_context.schema.json"))


# --------------------------------------------------------------------------- #
# Fix #1: the independent-review gate — no report over self-/orchestrator-attested findings
# --------------------------------------------------------------------------- #
class TestIndependentReviewGate(unittest.TestCase):
    """Redstrike's core guarantee is that a reportable finding is gated by an INDEPENDENT
    `<class>-verify` reviewer. A finding that reaches reporting but was "verified" only by the
    orchestrator itself ('orchestrator-self-verify') is self-attestation. Once a report exists this
    must FAIL unless an explicit operator-accept is recorded — and must never be a SILENT pass."""

    # -- unit: the roster + independence predicate --
    def test_roster_contains_real_verifiers(self):
        roster = vc._verify_roster()
        self.assertIn("cors-verify", roster)
        self.assertIn("xss-reflected-verify", roster)
        self.assertNotIn("orchestrator-self-verify", roster)

    def test_independence_predicate(self):
        roster = vc._verify_roster()
        self.assertTrue(vc._is_independent_reviewer("cors-verify", roster))
        self.assertFalse(vc._is_independent_reviewer("orchestrator-self-verify", roster))
        self.assertFalse(vc._is_independent_reviewer("", roster))
        self.assertFalse(vc._is_independent_reviewer("alice (operator)", roster))
        self.assertFalse(vc._is_independent_reviewer("made-up-verify", roster))  # -verify but not real
        # no-roster fallback: structural signal only
        self.assertTrue(vc._is_independent_reviewer("cors-verify", set()))
        self.assertFalse(vc._is_independent_reviewer("orchestrator-self-verify", set()))

    def _report_eng(self, d, *, reviewer, accept_reason=None):
        """An otherwise-complete, report-present engagement whose single finding carries `reviewer`.
        Satisfies the coverage + surface hard gates so ONLY the review gate is under test."""
        eng = pathlib.Path(d)
        f = valid_finding()
        f["review"] = {"verdict": "accepted", "reviewer": reviewer}
        (eng / "report").mkdir(parents=True, exist_ok=True)
        for item in f["evidence"]:
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        substantiate_attempted(led)  # a complete ledger's clears are depth-substantiated, not rubber-stamped
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)
        if accept_reason is not None:
            (eng / "reviews").mkdir(parents=True, exist_ok=True)
            (eng / "reviews" / "self_verified_accepts.json").write_text(
                json.dumps({f["id"]: accept_reason}), encoding="utf-8")
        return eng

    def test_self_verified_with_report_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d, reviewer="orchestrator-self-verify")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertFalse(payload["pass"], buf.getvalue())
            self.assertTrue(payload["review_errors"])
            self.assertIn("independent", " ".join(payload["review_errors"]).lower())

    def test_independent_reviewer_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d, reviewer="xss-reflected-verify")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["pass"], buf.getvalue())
            self.assertFalse(payload["review_errors"])

    def test_operator_accept_clears_the_hard_error(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d, reviewer="orchestrator-self-verify",
                                   accept_reason="no username-enumeration *-verify class exists yet")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["pass"], buf.getvalue())
            self.assertFalse(payload["review_errors"])
            # the acceptance is surfaced as a warning (visible, not silent) + names the backfill
            self.assertTrue(any("operator-accepted" in w for w in payload["warnings"]))

    def test_blank_accept_reason_is_not_an_accept(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d, reviewer="orchestrator-self-verify", accept_reason="   ")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertFalse(payload["pass"], buf.getvalue())
            self.assertTrue(payload["review_errors"])

    def test_no_report_self_verified_is_warning_not_failure(self):
        """Mid-hunt (no consolidated report): a self-verified finding is a warning, not a hard fail."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()
            f["review"] = {"verdict": "accepted", "reviewer": "orchestrator-self-verify"}
            write_evidence(eng, f)
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["pass"], buf.getvalue())
            self.assertFalse(payload["review_errors"])
            self.assertTrue(any("not an independent" in w for w in payload["warnings"]))


# --------------------------------------------------------------------------- #
# P0-1: coordination-artifact integrity gate — no report over an artifact that
# broke its OWN vocabulary (out-of-vocab signal / out-of-enum surface kind).
# --------------------------------------------------------------------------- #
class TestSignalsSchema(unittest.TestCase):
    """The signal-vocabulary schema validates a signals.json feeder document and rejects a token
    outside the closed vocabulary (the sink:dom-backlink leak shape)."""
    SCHEMA = "skills/_contract/signals.schema.json"

    def ok(self, doc):
        return vc._validate_against_schema(doc, self.SCHEMA)[0]

    def test_conformant_signals_doc_passes(self):
        self.assertTrue(self.ok({"signals": ["param:injectable", "sink:dom", "asset:cloud"]}))

    def test_out_of_vocab_signal_fails(self):
        self.assertFalse(self.ok({"signals": ["param:injectable", "sink:dom-backlink"]}))

    def test_vocab_matches_routing_map(self):
        schema = json.loads((REPO / self.SCHEMA).read_text(encoding="utf-8"))
        rmap = json.loads((REPO / "skills/_contract/routing-map.json").read_text(encoding="utf-8"))
        self.assertEqual(set(schema["$defs"]["signal"]["enum"]), set(rmap["signals"]))


class TestCoordinationIntegrityGate(unittest.TestCase):
    """Once a report exists, a coordination artifact that broke its own vocabulary — an out-of-vocab
    signal folded into coverage_ledger.signals_used / the inbox, or an out-of-enum surface kind in the
    surface ledger / inbox — HARD-fails (the noxframe sink:dom-backlink / `content`-surface leak)."""

    def _clean_report_eng(self, d):
        eng = pathlib.Path(d)
        f = valid_finding()  # reviewer xss-reflected-verify (independent), verdict accepted
        (eng / "report").mkdir(parents=True, exist_ok=True)
        for item in f["evidence"]:
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        substantiate_attempted(led)  # a complete ledger's clears are depth-substantiated, not rubber-stamped
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)
        return eng, led, sled

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    def test_clean_engagement_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng, _l, _s = self._clean_report_eng(d)
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["integrity_errors"], [])

    def test_inbox_out_of_vocab_signal_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng, _l, _s = self._clean_report_eng(d)
            (eng / "reconvergence").mkdir(parents=True, exist_ok=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "pp", "signals": ["sink:dom-backlink"]}) + "\n", encoding="utf-8")
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("sink:dom-backlink" in e for e in payload["integrity_errors"]))

    def test_inbox_content_kind_is_a_followup_not_an_error(self):
        # fix #5: a `content` discovery (sitemap/robots/API schema) in the inbox is a legitimate reroute to
        # content-discovery, NOT corruption — it must not hard-fail the coordination-integrity gate.
        with tempfile.TemporaryDirectory() as d:
            eng, _l, _s = self._clean_report_eng(d)
            (eng / "reconvergence").mkdir(parents=True, exist_ok=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "x", "surface": [{"kind": "content", "value": "/sitemap.xml"}]}) + "\n",
                encoding="utf-8")
            payload = self._run(eng)
            self.assertEqual(payload["integrity_errors"], [], payload)

    def test_inbox_truly_unknown_kind_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng, _l, _s = self._clean_report_eng(d)
            (eng / "reconvergence").mkdir(parents=True, exist_ok=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "x", "surface": [{"kind": "bogus-kind", "value": "/x"}]}) + "\n",
                encoding="utf-8")
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("bogus-kind" in e for e in payload["integrity_errors"]))

    def test_surface_ledger_out_of_enum_kind_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng, _l, sled = self._clean_report_eng(d)
            sled["surfaces"].append({"id": "content:abc", "kind": "content",
                                     "value": "/sitemap.xml", "status": "n/a", "reason": "x"})
            (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("surface_ledger.json" in e and "content" in e for e in payload["integrity_errors"]))

    def test_coverage_signals_used_out_of_vocab_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng, led, _s = self._clean_report_eng(d)
            led["signals_used"] = ["param:injectable", "sink:dom-backlink"]
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("signals_used" in e for e in payload["integrity_errors"]))

    def test_coverage_triggers_matched_out_of_vocab_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng, led, _s = self._clean_report_eng(d)
            for c in led["categories"]:
                if c["id"] == "xss":
                    c["triggers_matched"] = ["sink:dom-backlink"]  # out-of-vocab folded into a category entry
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("triggers_matched" in e and "sink:dom-backlink" in e
                                for e in payload["integrity_errors"]))

    def test_no_report_integrity_is_silent(self):
        """Mid-hunt (no consolidated report): a malformed inbox must NOT fail the gate."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()
            write_evidence(eng, f)
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            (eng / "reconvergence").mkdir(parents=True, exist_ok=True)
            (eng / "reconvergence" / "inbox.jsonl").write_text(
                json.dumps({"source": "x", "signals": ["sink:dom-backlink"]}) + "\n", encoding="utf-8")
            payload = self._run(eng)
            self.assertEqual(payload["integrity_errors"], [])


# --------------------------------------------------------------------------- #
# P1-1: recall-audit hard gate — no report over an un-closed shallow-clear /
# skipped-but-signalled / never-run gap (the false-negative altitude).
# --------------------------------------------------------------------------- #
class TestRecallAuditGate(unittest.TestCase):
    """The recall audit was advisory only — the noxframe report shipped over ~10 HIGH shallow-clear gaps.
    Once a report exists a gated recall gap must be closed (escalate + re-run) or explicitly accepted."""

    def _eng(self, d, *, shallow=True, escalated=False, accept=None):
        eng = pathlib.Path(d)
        f = valid_finding()  # independent reviewer, accepted
        (eng / "report").mkdir(parents=True, exist_ok=True)
        for item in f["evidence"]:
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        if shallow:
            # sqli: high-prior (a signal matched) but empty, ladder unexhausted => a shallow-clear gap
            sqli = next(c for c in led["categories"] if c["id"] == "sqli")
            sqli["triggers_matched"] = ["param:injectable"]
            sqli["findings_count"] = 0
            if escalated:
                sys.path.insert(0, str(REPO / "scripts"))
                import escalation  # noqa: E402
                sqli["escalations"] = escalation.ladder_for("sqli")
        # every zero-finding clear is depth-substantiated; sqli stays a *recall* shallow-clear only when its
        # escalation ladder is unexhausted (the recall gate reads `escalations`, independent of depth fields).
        substantiate_attempted(led)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)
        if accept is not None:
            (eng / "reviews").mkdir(parents=True, exist_ok=True)
            (eng / "reviews" / "recall_audit_accepts.json").write_text(json.dumps(accept), encoding="utf-8")
        return eng

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    def test_shallow_clear_fails(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(self._eng(d, shallow=True))
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["recall_errors"])
            self.assertTrue(any("sqli" in e and "shallow-clear" in e for e in payload["recall_errors"]))

    def test_no_shallow_clear_passes(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(self._eng(d, shallow=False))
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["recall_errors"], [])

    def test_exhausted_ladder_is_not_a_gap(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(self._eng(d, shallow=True, escalated=True))
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["recall_errors"], [])

    def test_typed_accept_clears(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(self._eng(d, shallow=True,
                                          accept={"shallow-clear:sqli": "unseeded test DB, no rows to extract"}))
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["recall_errors"], [])
            self.assertTrue(any("operator-accepted" in w for w in payload["warnings"]))

    def test_bare_category_accept_clears(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(self._eng(d, shallow=True, accept={"sqli": "deliberately deferred to retest"}))
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["recall_errors"], [])

    def test_blank_accept_reason_is_not_an_accept(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(self._eng(d, shallow=True, accept={"shallow-clear:sqli": "   "}))
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["recall_errors"])

    def test_no_report_recall_is_silent(self):
        """Mid-hunt (no consolidated report): a shallow-clear ledger must NOT fail the gate."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()
            write_evidence(eng, f)
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            cov = vc._try_import_coverage()
            led = cov.plan(cov.load_map(), None, {"web"})
            sqli = next(c for c in led["categories"] if c["id"] == "sqli")
            sqli["status"], sqli["findings_count"] = "attempted", 0
            sqli["triggers_matched"] = ["param:injectable"]
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            self.assertEqual(vc._recall_hard_errors(eng), [])


# --------------------------------------------------------------------------- #
# P2-1: cleanup/reversion gate — a post-ex/persistence finding must prove
# verified reversion with a structured `cleanup` object, not prose.
# --------------------------------------------------------------------------- #
class TestCleanupReversionGate(unittest.TestCase):
    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def _persistence_finding(self, eng, *, cleanup="valid"):
        f = valid_finding(category={"cwe": "CWE-507"})
        f["_rs_source_skill"] = "persistence"
        write_evidence(eng, f)
        if cleanup == "valid":
            ref = "findings/evidence/cleanup.md"
            (eng / ref).parent.mkdir(parents=True, exist_ok=True)
            (eng / ref).write_text("removed the scheduled task; schtasks /query confirms gone\n", encoding="utf-8")
            f["cleanup"] = {"mechanism": "scheduled task benign marker", "removed": True,
                            "verified_by": "schtasks /query shows the task is gone", "ref": ref}
        elif cleanup == "not-removed":
            ref = "findings/evidence/cleanup.md"
            (eng / ref).parent.mkdir(parents=True, exist_ok=True)
            (eng / ref).write_text("left in place\n", encoding="utf-8")
            f["cleanup"] = {"mechanism": "run key", "removed": False,
                            "verified_by": "n/a", "ref": ref}
        elif cleanup == "missing-ref":
            f["cleanup"] = {"mechanism": "run key", "removed": True,
                            "verified_by": "reg query", "ref": "findings/evidence/nope.md"}
        # cleanup == "absent" -> no cleanup object
        return f

    def test_persistence_without_cleanup_fails(self):
        eng = self._eng()
        f = self._persistence_finding(eng, cleanup="absent")
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("cleanup", detail)

    def test_persistence_with_verified_cleanup_passes(self):
        eng = self._eng()
        f = self._persistence_finding(eng, cleanup="valid")
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok, detail)

    def test_persistence_removed_false_fails(self):
        eng = self._eng()
        f = self._persistence_finding(eng, cleanup="not-removed")
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("removed", detail)

    def test_persistence_missing_cleanup_ref_fails(self):
        eng = self._eng()
        f = self._persistence_finding(eng, cleanup="missing-ref")
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)
        self.assertIn("cleanup ref not found", detail)

    def test_web_finding_needs_no_cleanup(self):
        eng = self._eng()
        f = valid_finding()  # no _rs_source_skill -> not a post-ex class
        write_evidence(eng, f)
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertTrue(ok, detail)

    def test_credential_access_also_requires_cleanup(self):
        eng = self._eng()
        f = self._persistence_finding(eng, cleanup="absent")
        f["_rs_source_skill"] = "credential-access"
        ok, detail, _ = vc.check_finding(f, eng, SCOPE_YAML, None, set())
        self.assertFalse(ok)

    def test_engagement_per_skill_persistence_without_cleanup_hard_fails(self):
        """A persistence finding discovered via the per-skill layout (tagged by dir) without a verified
        cleanup object must FAIL the engagement gate."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding(category={"cwe": "CWE-507"})
            write_evidence(eng, f)  # evidence resolves from eng root
            (eng / "persistence").mkdir()
            (eng / "persistence" / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ok = vc.validate_engagement(eng, as_json=True)
            payload = json.loads(buf.getvalue())
            self.assertFalse(payload["pass"], buf.getvalue())
            self.assertTrue(any("cleanup" in r["detail"] for r in payload["results"] if not r["passed"]))


# --------------------------------------------------------------------------- #
# P2-2: attack-chain integrity gate — chain steps resolve to accepted/blocked
# findings; chain findings are composite.
# --------------------------------------------------------------------------- #
class TestAttackChainGate(unittest.TestCase):
    def _clean_report_eng(self, d):
        eng = pathlib.Path(d)
        f = valid_finding()  # id RS-2026-001, accepted by an independent reviewer
        (eng / "report").mkdir(parents=True, exist_ok=True)
        for item in f["evidence"]:
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        substantiate_attempted(led)  # a complete ledger's clears are depth-substantiated, not rubber-stamped
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)
        return eng

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    def _write_chains(self, eng, steps):
        (eng / "attack-chain-discovery").mkdir(parents=True, exist_ok=True)
        (eng / "attack-chain-discovery" / "chains.json").write_text(json.dumps(
            {"target": "app.acme.com", "generated_at": "2026-01-01T00:00:00Z",
             "chains": [{"id": "chain-001", "title": "demo", "steps": steps}]}), encoding="utf-8")

    def test_chain_on_known_accepted_finding_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._clean_report_eng(d)
            self._write_chains(eng, [{"finding_id": "RS-2026-001", "role": "entry"},
                                     {"finding_id": "RS-2026-001", "role": "exfil"}])
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["chain_errors"], [])

    def test_chain_on_unknown_finding_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._clean_report_eng(d)
            self._write_chains(eng, [{"finding_id": "RS-2026-001", "role": "entry"},
                                     {"finding_id": "RS-2026-999", "role": "exfil"}])
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("RS-2026-999" in e for e in payload["chain_errors"]))


# --------------------------------------------------------------------------- #
# Phase 2 (reliability): runtime/diagnostics.json consumers
#   (a) transport-blocked coverage AUTO-POPULATE
#   (b) the zero-finding-report diagnostics HARD gate (empty ≠ clean)
# Built against the pinned diagnostics.json contract with fixtures (Phase 1 owns
# the producer + schema; this exercises the CONSUMER only).
# --------------------------------------------------------------------------- #
def _diag_doc(*, outcome="clean-tested", degraded_reason=None, blocked_hosts=None, findings_count=0):
    """A minimal runtime/diagnostics.json matching the pinned contract: one run with the given
    outcome, plus optional transport_health hosts classified 'blocked'. `findings_count` defaults to 0
    (the zero-finding fixtures); set it for the report-WITH-findings consistency cases."""
    hosts = []
    worst = None
    for host, rate, waf in (blocked_hosts or []):
        hosts.append({"host": host, "requests": 100, "blocks": int(rate * 100), "block_rate": rate,
                      "statuses": {"403": int(rate * 100)}, "challenges": 0, "waf": waf,
                      "classification": "blocked"})
        if worst is None or rate > worst[1]:
            worst = (host, rate)
    run = {"session": "s1", "mode": "autonomous", "started": "2026-01-01T00:00:00Z",
           "ended": "2026-01-01T01:00:00Z", "engine_rc": 0, "gate_rc": None,
           "outcome": outcome, "degraded_reason": degraded_reason,
           "findings_count": findings_count, "tool_failures": [], "exceptions": [],
           "transport_health": {"hosts": hosts,
                                "overall": {"block_rate": (worst[1] if worst else 0.0),
                                            "worst_host": (worst[0] if worst else None),
                                            "status": "blocked" if hosts else "healthy"}},
           "empty_recon": {}, "phase_tally": [], "gate_summary": {}}
    if outcome is None:
        del run["outcome"]
    return {"engagement": "acme-2026", "generated_at": "2026-01-01T01:00:00Z", "runs": [run]}


def _write_diag(eng, doc):
    (eng / "runtime").mkdir(parents=True, exist_ok=True)
    (eng / "runtime" / "diagnostics.json").write_text(json.dumps(doc), encoding="utf-8")


class TestDiagnosticsHelpers(unittest.TestCase):
    """The pure diagnostics readers: latest-run selection + transport-blocked host extraction."""

    def test_latest_run_picks_last(self):
        doc = {"runs": [{"outcome": "failed"}, {"outcome": "clean-tested"}]}
        self.assertEqual(vc._latest_run(doc)["outcome"], "clean-tested")
        self.assertIsNone(vc._latest_run({"runs": []}))
        self.assertIsNone(vc._latest_run({}))
        self.assertIsNone(vc._latest_run(None))

    def test_blocked_hosts_worst_first(self):
        run = _diag_doc(blocked_hosts=[("a.acme.com", 0.4, "cloudflare"),
                                       ("b.acme.com", 0.9, None)])["runs"][0]
        got = vc._transport_blocked_hosts(run)
        self.assertEqual([h[0] for h in got], ["b.acme.com", "a.acme.com"])  # worst (0.9) first
        self.assertEqual(got[0][2], None)

    def test_blocked_hosts_ignores_healthy(self):
        run = {"transport_health": {"hosts": [{"host": "x", "classification": "healthy", "block_rate": 0.0}]}}
        self.assertEqual(vc._transport_blocked_hosts(run), [])

    def test_transport_reason_format(self):
        r = vc._transport_reason("app.acme.com", 0.82, "cloudflare")
        self.assertTrue(r.startswith("transport: WAF block_rate "))
        self.assertIn("82%", r)
        self.assertIn("app.acme.com", r)
        self.assertIn("cloudflare", r)
        # null WAF → a readable placeholder, never "None"
        self.assertIn("WAF unidentified", vc._transport_reason("h", 0.5, None))


class TestTransportBlockedAutoPopulate(unittest.TestCase):
    """(a) A transport-`blocked` host auto-marks web coverage categories still pending / attempted-empty
    as `blocked` with a transport-sourced reason — sourced from transport health, not the model."""

    def _ledger(self, eng):
        led = {"engagement": "acme-2026", "generated_at": "2026-01-01T00:00:00Z",
               "active_phases": ["web"], "categories": [
                   {"id": "sqli", "phase": "web", "status": "pending", "reason": "baseline"},
                   {"id": "xss", "phase": "web", "status": "attempted", "reason": "ran", "findings_count": 0},
                   {"id": "idor", "phase": "web", "status": "attempted", "reason": "ran", "findings_count": 2},
                   {"id": "csrf", "phase": "web", "status": "skipped", "reason": "no state-change surface"},
                   {"id": "ad-kerberos", "phase": "ad", "status": "pending", "reason": "foothold"},
               ]}
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")

    def _by_id(self, eng):
        led = json.loads((eng / "coverage_ledger.json").read_text(encoding="utf-8"))
        return {c["id"]: c for c in led["categories"]}

    def test_flips_pending_and_empty_web_only(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._ledger(eng)
            _write_diag(eng, _diag_doc(blocked_hosts=[("app.acme.com", 0.88, "akamai")]))
            flipped = vc._auto_populate_blocked_coverage(eng)
            self.assertEqual(set(flipped), {"sqli", "xss"})
            by = self._by_id(eng)
            self.assertEqual(by["sqli"]["status"], "blocked")
            self.assertTrue(by["sqli"]["reason"].startswith("transport: WAF block_rate"))
            self.assertIn("app.acme.com", by["xss"]["reason"])
            self.assertEqual(by["idor"]["status"], "attempted")     # has findings → kept
            self.assertEqual(by["csrf"]["status"], "skipped")        # deliberate skip → kept
            self.assertEqual(by["ad-kerberos"]["status"], "pending") # non-web phase → untouched

    def test_no_diagnostics_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._ledger(eng)
            self.assertEqual(vc._auto_populate_blocked_coverage(eng), [])
            self.assertEqual(self._by_id(eng)["sqli"]["status"], "pending")  # unchanged

    def test_healthy_transport_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._ledger(eng)
            _write_diag(eng, _diag_doc(outcome="clean-tested"))  # no blocked hosts
            self.assertEqual(vc._auto_populate_blocked_coverage(eng), [])
            self.assertEqual(self._by_id(eng)["xss"]["status"], "attempted")

    def test_blocked_but_no_ledger_is_noop(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            _write_diag(eng, _diag_doc(blocked_hosts=[("app.acme.com", 0.9, "cloudflare")]))
            self.assertEqual(vc._auto_populate_blocked_coverage(eng), [])


class TestDiagnosticsZeroFindingGate(unittest.TestCase):
    """(b) A zero-finding report must carry an EXPLAINED diagnostics outcome (empty ≠ clean). HARD once a
    consolidated report exists and no reportable finding reached it."""

    def _zero_finding_report_eng(self, d):
        """A report-present engagement with ZERO findings that satisfies every OTHER hard gate
        (complete coverage ledger + a tested surface ledger), so ONLY the diagnostics gate is under test."""
        eng = pathlib.Path(d)
        (eng / "report").mkdir(parents=True, exist_ok=True)
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": []}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        substantiate_attempted(led)  # a complete ledger's clears are depth-substantiated, not rubber-stamped
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)
        return eng

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    def test_missing_diagnostics_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)  # no runtime/diagnostics.json
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["diagnostics_errors"])
            self.assertIn("empty ≠ clean", " ".join(payload["diagnostics_errors"]))

    def test_clean_tested_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)
            _write_diag(eng, _diag_doc(outcome="clean-tested"))
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["diagnostics_errors"], [])

    def test_degraded_empty_with_reason_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)
            _write_diag(eng, _diag_doc(outcome="degraded-empty",
                                       degraded_reason="target returned 503 for the whole window"))
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["diagnostics_errors"], [])

    def test_failed_with_reason_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)
            _write_diag(eng, _diag_doc(outcome="failed", degraded_reason="engine crashed mid-run"))
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)

    def test_degraded_empty_without_reason_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)
            _write_diag(eng, _diag_doc(outcome="degraded-empty", degraded_reason=None))
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("degraded_reason" in e for e in payload["diagnostics_errors"]))

    def test_missing_outcome_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)
            _write_diag(eng, _diag_doc(outcome=None))
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["diagnostics_errors"])

    def test_produced_findings_outcome_but_empty_report_fails(self):
        """A contradiction: diagnostics says 'produced-findings' but the report carries none."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._zero_finding_report_eng(d)
            _write_diag(eng, _diag_doc(outcome="produced-findings"))
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["diagnostics_errors"])

    def test_report_with_findings_does_not_require_diagnostics(self):
        """The gate applies ONLY to a zero-finding report; a report WITH a reportable finding and no
        diagnostics.json must not trip it."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            f = valid_finding()  # accepted by an independent reviewer
            (eng / "report").mkdir(parents=True, exist_ok=True)
            for item in f["evidence"]:
                p = eng / item["ref"]
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
            (eng / "report" / "findings_consolidated.json").write_text(
                json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            cov = vc._try_import_coverage()
            led = cov.plan(cov.load_map(), None, {"web"})
            for c in led["categories"]:
                if c["status"] == "pending":
                    c["status"], c["findings_count"] = "attempted", 0
            substantiate_attempted(led)  # clears are depth-substantiated, not rubber-stamped
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            sf = vc._try_import_surface()
            sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
            for s in sled["surfaces"]:
                if s["status"] == "discovered":
                    s["status"] = "tested"
            (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
            write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete'
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["diagnostics_errors"], [])

    def test_no_report_is_silent(self):
        """Mid-hunt (no consolidated report): zero findings + no diagnostics must NOT fail."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            (eng / "findings.json").write_text(json.dumps([]), encoding="utf-8")
            self.assertEqual(vc._diagnostics_hard_errors(eng, []), [])


class TestDiagnosticsAutoPopulateIntegration(unittest.TestCase):
    """End-to-end: a zero-finding report over a WAF-blocked host passes ONLY because auto-populate
    converts the otherwise-pending web categories to `blocked` (so the coverage gate is satisfied) AND
    the diagnostics outcome explains the empty — the two reliability surfaces working together."""

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    def test_blocked_run_autopopulates_and_passes_with_explained_outcome(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "report").mkdir(parents=True, exist_ok=True)
            (eng / "report" / "findings_consolidated.json").write_text(
                json.dumps({"engagement": "acme-2026", "findings": []}), encoding="utf-8")
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            cov = vc._try_import_coverage()
            led = cov.plan(cov.load_map(), None, {"web"})  # every web class left `pending`
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            sf = vc._try_import_surface()
            sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
            for s in sled["surfaces"]:
                if s["status"] == "discovered":
                    s["status"] = "tested"
            (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
            _write_diag(eng, _diag_doc(outcome="degraded-empty",
                                       degraded_reason="WAF blocked the engagement",
                                       blocked_hosts=[("app.acme.com", 0.95, "cloudflare")]))
            write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete'
            payload = self._run(eng)
            # the ledger was auto-rewritten: no web category left pending (would have been a coverage gap)
            after = {c["id"]: c for c in json.loads(
                (eng / "coverage_ledger.json").read_text(encoding="utf-8"))["categories"]}
            web = [c for c in after.values() if c["phase"] == "web"]
            self.assertTrue(web, "expected web categories in the ledger")
            self.assertFalse(any(c["status"] == "pending" for c in web),
                             "auto-populate should flip every pending web category to blocked")
            self.assertTrue(any(c["status"] == "blocked" for c in web))
            self.assertTrue(payload["pass"], payload)
            self.assertTrue(any("transport-blocked" in w for w in payload["warnings"]))

    def test_blocked_run_without_explained_outcome_still_fails(self):
        """Auto-populate fixes the coverage gap, but an UNEXPLAINED empty still fails the diagnostics gate
        — the block being visible on the ledger does not excuse an un-attested empty report."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "report").mkdir(parents=True, exist_ok=True)
            (eng / "report" / "findings_consolidated.json").write_text(
                json.dumps({"engagement": "acme-2026", "findings": []}), encoding="utf-8")
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            cov = vc._try_import_coverage()
            led = cov.plan(cov.load_map(), None, {"web"})
            (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
            sf = vc._try_import_surface()
            sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
            for s in sled["surfaces"]:
                if s["status"] == "discovered":
                    s["status"] = "tested"
            (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
            _write_diag(eng, _diag_doc(outcome=None,
                                       blocked_hosts=[("app.acme.com", 0.95, "cloudflare")]))
            write_exhaustion_review(eng)  # isolate the diagnostics gate (exhaustion gate satisfied)
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["diagnostics_errors"])
            self.assertFalse(payload["coverage_errors"])  # coverage gap was auto-resolved


# --------------------------------------------------------------------------- #
# Fix #3b: a report WITH findings must not carry a STALE latest run that contradicts it (the interactive
# Skill path writes no run record, so runs[-1] stays a stale degraded CLI-init entry — a false "degraded").
# --------------------------------------------------------------------------- #
class TestDiagnosticsStaleFindingsGate(unittest.TestCase):
    """Once a report WITH reportable findings exists, a latest diagnostics run whose outcome/findings_count
    contradict it HARD-fails (run scripts/close.py). A report WITH findings and NO diagnostics file stays a
    non-error — there is nothing stale to contradict."""

    def _report_with_finding_eng(self, d):
        """A report-present engagement with ONE reportable finding that satisfies every OTHER hard gate, so
        ONLY the diagnostics stale-findings gate is under test."""
        eng = pathlib.Path(d)
        f = valid_finding()  # independent reviewer, accepted → reportable
        (eng / "report").mkdir(parents=True, exist_ok=True)
        for item in f["evidence"]:
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        substantiate_attempted(led)  # a complete ledger's clears are depth-substantiated, not rubber-stamped
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        write_exhaustion_review(eng)  # cross-model adversary could not disprove 'complete' (report-ready)
        return eng

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    def test_stale_degraded_run_contradicts_findings_report_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_with_finding_eng(d)
            # the exact stale entry the Skill path leaves: degraded-empty, findings_count 0
            _write_diag(eng, _diag_doc(outcome="degraded-empty",
                                       degraded_reason="blocked on approval", findings_count=0))
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["diagnostics_errors"])
            joined = " ".join(payload["diagnostics_errors"])
            self.assertIn("close.py", joined)
            self.assertIn("stale", joined)

    def test_fresh_produced_run_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_with_finding_eng(d)
            _write_diag(eng, _diag_doc(outcome="produced-findings", findings_count=1))
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["diagnostics_errors"], [])

    def test_produced_outcome_but_zero_count_fails(self):
        """produced-findings but findings_count 0 is still a contradiction (a half-stale record)."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_with_finding_eng(d)
            _write_diag(eng, _diag_doc(outcome="produced-findings", findings_count=0))
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["diagnostics_errors"])

    def test_findings_report_without_diagnostics_is_ok(self):
        """Back-compat: a report WITH findings and NO diagnostics.json must NOT trip the gate."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_with_finding_eng(d)  # no runtime/diagnostics.json
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["diagnostics_errors"], [])


# --------------------------------------------------------------------------- #
# Tier-1 #3: the cross-model EXHAUSTION-ADVERSARY gate — no report unless the
# model-pinned adversary was UNABLE to disprove "engagement complete / class
# exhausted" (runtime/exhaustion_review.json → verdict=no_gaps_found, every gap
# closed). Un-routable, like the secondary-review gate: no operator-accept hatch.
# --------------------------------------------------------------------------- #
class TestExhaustionAdversaryGate(unittest.TestCase):
    """The mechanical + per-class + recall gates prove only "no failure the gate knows how to detect".
    None of them disproves the top-level "complete / exhausted" claim, and a same-model self-check is
    worthless. Once a report exists, the cross-model exhaustion-adversary's no_gaps_found verdict is
    REQUIRED (with every gap it raised closed); a missing artifact, a found_gaps verdict, or an open gap
    HARD-fails — the engagement is not report-ready."""

    def _report_eng(self, d):
        """A report-present engagement that satisfies every OTHER hard gate (independent-reviewed accepted
        finding + complete coverage + tested surface), so ONLY the exhaustion-adversary gate is under test.
        Deliberately writes NO runtime/exhaustion_review.json — each test supplies (or omits) its own."""
        eng = pathlib.Path(d)
        f = valid_finding()  # accepted by an independent reviewer + secondary_review present
        (eng / "report").mkdir(parents=True, exist_ok=True)
        for item in f["evidence"]:
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        cov = vc._try_import_coverage()
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"], c["findings_count"] = "attempted", 0
        substantiate_attempted(led)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sf = vc._try_import_surface()
        sled = sf.plan_from_items("acme-2026", [{"kind": "endpoint", "value": "/s", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        return eng

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue())

    # -- unit: the pure helpers --
    def test_open_gaps_helper(self):
        # a bare gap (no status) and an explicitly-open gap are OPEN; closed/resolved/redriven are not.
        review = {"gaps": [
            {"category": "sqli", "gap": "ladder unexhausted", "remediation": "run time-based"},
            {"category": "xss", "gap": "no depth", "remediation": "encode", "status": "open"},
            {"category": "idor", "gap": "fixed", "remediation": "n/a", "status": "redriven"},
            {"host": "api.acme.com", "gap": "untested", "remediation": "test it", "status": "closed",
             "blocker": "single-identity"},
        ]}
        open_ = vc._exhaustion_open_gaps(review)
        self.assertEqual(len(open_), 2)
        self.assertTrue(any("sqli" in g for g in open_))
        self.assertTrue(any("xss" in g for g in open_))
        self.assertFalse(any("idor" in g or "api.acme.com" in g for g in open_))

    def test_load_missing_is_none(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(vc._load_exhaustion_review(pathlib.Path(d)))

    # -- should-FAIL: report present, no exhaustion review at all --
    def test_report_without_exhaustion_review_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d)  # no runtime/exhaustion_review.json
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(payload["exhaustion_review_errors"])
            self.assertIn("exhaustion", " ".join(payload["exhaustion_review_errors"]).lower())

    # -- should-FAIL: a found_gaps verdict (the adversary DID disprove 'complete') --
    def test_found_gaps_verdict_fails_and_names_the_gap(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d)
            write_exhaustion_review(eng, verdict="found_gaps", gaps=[
                {"category": "ssrf", "type": "blocked-never-redriven", "status": "open",
                 "gap": "ssrf left blocked; non-destructive detection never ran",
                 "remediation": "re-drive ssrf non-destructive detection against api.acme.com"}])
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            joined = " ".join(payload["exhaustion_review_errors"])
            self.assertIn("ssrf", joined)              # the gap→re-drivable signal: names the class
            self.assertIn("re-drive", joined.lower())  # ...and the concrete remediation

    # -- should-FAIL: verdict claims no_gaps_found but a gap is still OPEN (inconsistent) --
    def test_no_gaps_found_but_open_gap_fails(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d)
            write_exhaustion_review(eng, verdict="no_gaps_found", gaps=[
                {"category": "idor", "gap": "second identity never tried", "status": "open",
                 "remediation": "re-run idor with the second test identity"}])
            payload = self._run(eng)
            self.assertFalse(payload["pass"], payload)
            self.assertTrue(any("OPEN" in e for e in payload["exhaustion_review_errors"]))

    # -- should-PASS: a clean no_gaps_found verdict --
    def test_no_gaps_found_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d)
            write_exhaustion_review(eng, verdict="no_gaps_found")
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["exhaustion_review_errors"], [])

    # -- should-PASS: no_gaps_found WITH a genuinely-unclosable gap carried as closed + a named blocker --
    def test_no_gaps_found_with_blocker_closed_gap_passes(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._report_eng(d)
            write_exhaustion_review(eng, verdict="no_gaps_found", gaps=[
                {"category": "xss-blind", "gap": "no OOB collaborator to confirm blind execution",
                 "remediation": "re-run with an OOB collaborator when one is in scope",
                 "status": "closed", "blocker": "no-oob-collaborator"}])
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["exhaustion_review_errors"], [])

    # -- schema: the verdict artifact validates against the house schema --
    def test_artifact_validates_against_schema(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            write_exhaustion_review(eng, verdict="found_gaps", gaps=[
                {"host": "api.acme.com", "gap": "untested surface", "remediation": "test it",
                 "severity": "high", "status": "open", "type": "no-evidence-artifact"}])
            doc = json.loads((eng / "runtime" / "exhaustion_review.json").read_text(encoding="utf-8"))
            ok, note = vc._validate_against_schema(doc, "skills/_contract/exhaustion_review.schema.json")
            self.assertTrue(ok, note)
            # a gap with NEITHER category NOR host violates the anyOf
            bad = dict(doc)
            bad["gaps"] = [{"gap": "x", "remediation": "y"}]
            ok2, _ = vc._validate_against_schema(bad, "skills/_contract/exhaustion_review.schema.json")
            self.assertFalse(ok2)

    # -- mid-hunt: no report → the gate is a WARNING, never a hard fail (behavior unchanged pre-close) --
    def test_no_report_is_silent(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()
            write_evidence(eng, f)
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            payload = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertEqual(payload["exhaustion_review_errors"], [])
            self.assertTrue(any("exhaustion" in w.lower() for w in payload["warnings"]))


# --------------------------------------------------------------------------- #
# Cross-model DIVERSITY-VISIBILITY (roadmap L-H): MEASURE what the `model:` pin
# ASSERTS. A WARNING (never a hard fail) + a recorded deliverable fact when the
# ACTUAL dispatched model collapsed to same-model — never a silent same-model pass.
# --------------------------------------------------------------------------- #
class TestModelDiversityVisibility(unittest.TestCase):
    def _complete_report_eng(self, d, *, exhaustion_model="sonnet"):
        """A report-present engagement that passes EVERY hard gate, so the diversity WARNING is the only thing
        that varies. Mirrors TestCoverageGateReportPresent._write_report + a complete coverage/surface ledger."""
        eng = pathlib.Path(d)
        cov = vc._try_import_coverage()
        sf = vc._try_import_surface()
        self.assertIsNotNone(cov)
        self.assertIsNotNone(sf)
        f = valid_finding()
        for item in f.get("evidence", []):
            p = eng / item["ref"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("req\n\nHTTP/1.1 200\n<svg/onload=alert(1)>\n", encoding="utf-8")
        (eng / "report").mkdir(parents=True, exist_ok=True)
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps({"engagement": "acme-2026", "findings": [f]}), encoding="utf-8")
        (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
        write_exhaustion_review(eng, model=exhaustion_model)
        led = cov.plan(cov.load_map(), None, {"web"})
        for c in led["categories"]:
            if c["status"] == "pending":
                c["status"] = "attempted"
                c["findings_count"] = 0
        substantiate_attempted(led)
        (eng / "coverage_ledger.json").write_text(json.dumps(led), encoding="utf-8")
        sled = sf.plan_from_items("acme-2026", [
            {"kind": "endpoint", "value": "/api/login", "discovered_by": "recon"},
            {"kind": "param", "value": "id", "discovered_by": "recon"}])
        for s in sled["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        (eng / "surface_ledger.json").write_text(json.dumps(sled), encoding="utf-8")
        return eng

    def _run(self, eng):
        buf = io.StringIO()
        with redirect_stdout(buf):
            vc.validate_engagement(eng, as_json=True)
        return json.loads(buf.getvalue()), buf

    def _diversity_warns(self, payload):
        return [w for w in payload["warnings"] if "cross-model diversity" in w.lower()]

    def test_missing_ledger_with_report_warns(self):
        """A report exists but no model_ledger.json — the actual dispatched model was never recorded, so
        diversity could not be MEASURED => a WARNING (non-failing), never a silent pass."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._complete_report_eng(d)  # no model ledger written
            payload, _ = self._run(eng)
            self.assertTrue(payload["pass"], payload)                 # gate still PASSES (warning, not fail)
            self.assertEqual(payload["exhaustion_review_errors"], [])  # the hard gate is untouched
            self.assertTrue(self._diversity_warns(payload), payload["warnings"])
            self.assertTrue(payload["diversity"]["warned"])
            # the warning must NOT be in any hard-error list
            self.assertFalse(any("diversity" in e.lower() for e in payload["exhaustion_review_errors"]))

    def test_all_same_model_warns(self):
        """Executors + reviewer + adversary ALL ran on opus (the real incident: a safeguard forced one model)
        => cross-model collapsed to same-model => a WARNING + cross_model_available False, gate still passes."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._complete_report_eng(d, exhaustion_model="opus")  # self-report matches the ledger
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "reviewer", "xss", "opus", agent_id="xss-reflected-verify")
            ml.record(eng, "exhaustion-adversary", None, "claude-opus-4-8")  # STILL opus
            payload, _ = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertFalse(payload["diversity"]["available"])
            self.assertTrue(payload["diversity"]["warned"])
            self.assertFalse(payload["diversity"]["self_report_mismatch"])  # self-report agrees, just same-model
            self.assertTrue(self._diversity_warns(payload), payload["warnings"])

    def test_cross_model_is_silent(self):
        """The adversary genuinely ran on a DIFFERENT family than the executors => NO diversity warning."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._complete_report_eng(d, exhaustion_model="sonnet")
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "executor", "sqli", "claude-opus-4-8")
            ml.record(eng, "exhaustion-adversary", None, "sonnet")  # different family — real cross-model
            payload, _ = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertTrue(payload["diversity"]["available"])
            self.assertFalse(payload["diversity"]["warned"])
            self.assertEqual(self._diversity_warns(payload), [], payload["warnings"])

    def test_self_report_mismatch_is_a_stronger_warning(self):
        """exhaustion_review SELF-REPORTS sonnet, but the ledger shows the adversary actually ran on opus —
        the asserted cross-model claim DISAGREES with what ran => a stronger (mismatch) WARNING, gate passes."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._complete_report_eng(d, exhaustion_model="sonnet")  # claims sonnet
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "exhaustion-adversary", None, "opus")  # but ACTUALLY ran on opus
            payload, _ = self._run(eng)
            self.assertTrue(payload["pass"], payload)
            self.assertTrue(payload["diversity"]["self_report_mismatch"])
            self.assertTrue(any("disagrees with what ran" in w.lower() or "asserted" in w.lower()
                                for w in self._diversity_warns(payload)), payload["warnings"])

    def test_non_report_engagement_unaffected(self):
        """Mid-hunt (no consolidated report): even a same-model ledger must NOT raise a diversity warning."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(SCOPE_YAML, encoding="utf-8")
            f = valid_finding()
            write_evidence(eng, f)
            (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "exhaustion-adversary", None, "opus")  # same model, but no report => silent
            payload, _ = self._run(eng)
            self.assertEqual(self._diversity_warns(payload), [], payload["warnings"])
            self.assertFalse(payload["diversity"]["warned"])

    def test_exhaustion_hard_gate_pass_condition_unchanged(self):
        """The diversity work must NOT convert the exhaustion gate into a model-equality hard-fail: a
        same-model engagement with a no_gaps_found verdict still PASSES the hard gate (only a warning fires),
        and a found_gaps verdict still HARD-fails — regardless of the model ledger."""
        with tempfile.TemporaryDirectory() as d:
            eng = self._complete_report_eng(d, exhaustion_model="opus")
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "exhaustion-adversary", None, "opus")  # same model (would 'fail' if diversity were hard)
            payload, _ = self._run(eng)
            self.assertTrue(payload["pass"], payload)                 # no_gaps_found still PASSES
            self.assertEqual(payload["exhaustion_review_errors"], [])  # diversity added NO hard error
        with tempfile.TemporaryDirectory() as d:
            eng = self._complete_report_eng(d, exhaustion_model="sonnet")
            write_exhaustion_review(eng, verdict="found_gaps",
                                    gaps=[{"category": "sqli", "gap": "never ran", "remediation": "run it",
                                           "status": "open"}], model="sonnet")
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "exhaustion-adversary", None, "sonnet")  # genuine cross-model, but a found_gap
            payload, _ = self._run(eng)
            self.assertFalse(payload["pass"], payload)                # found_gaps still HARD-fails
            self.assertTrue(payload["exhaustion_review_errors"])


if __name__ == "__main__":
    unittest.main()
