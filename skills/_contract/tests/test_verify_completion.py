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

import verify_completion as vc  # noqa: E402


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
        # 79 findings.json + cve_intel.json + the pre-existing attack_chain ref
        self.assertGreaterEqual(refs, 80, "expected the finding/cve_intel schema wiring to be present")


if __name__ == "__main__":
    unittest.main()
