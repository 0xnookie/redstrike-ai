#!/usr/bin/env python3
"""
Fix #5 — serve-time schema validation for scripts/console.py.

Covers the shared structural validator (scripts/structvalidate.py) and the console's
serve-time `_validate` wiring: every engagement artifact is checked against its
_contract schema and gets a NON-FATAL `_contract_violations[]`, with bad rows dropped
so one malformed row can't blank a view (degraded, not blank). The headline guard is the
js-analysis drift that broke the console (library->name / provider->provider_meta /
note->context / count->snippet) — the canonical field names are now locked.

Stdlib only, runnable as `python test_console_validate.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]                   # scripts/
ROOT = SCRIPTS.parent                       # repo root
sys.path.insert(0, str(SCRIPTS))

import structvalidate as sv  # noqa: E402
import console as c          # noqa: E402

CONTRACT = ROOT / "skills" / "_contract"
NEW_SCHEMAS = ["js_findings.schema.json", "content.schema.json",
               "http_history.schema.json", "scope.schema.json"]


def mk(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


# --------------------------------------------------------------------------- #
class TestStructValidatorCore(unittest.TestCase):
    def test_selftest_passes(self):
        sv.selftest()  # raises on any assertion failure

    def test_never_raises_on_garbage(self):
        # a malformed schema node must be reported, not raised
        self.assertIsInstance(sv.validate({"x": 1}, {"type": "object", "properties": 5}), list)
        self.assertEqual(sv.validate(5, True), [])

    def test_bool_is_not_integer(self):
        s = {"type": "object", "properties": {"n": {"type": "integer"}}}
        self.assertTrue(sv.validate({"n": True}, s))
        self.assertEqual(sv.validate({"n": 3}, s), [])

    def test_numeric_range(self):
        s = {"properties": {"epss": {"type": "number", "minimum": 0, "maximum": 1}}}
        self.assertEqual(sv.validate({"epss": 0.5}, s), [])
        self.assertTrue(sv.validate({"epss": 1.5}, s))

    def test_lenient_skips_required_additional_pattern(self):
        s = {"type": "object", "required": ["id"], "additionalProperties": False,
             "properties": {"id": {"type": "string", "pattern": "^RS-"}}}
        # strict: missing required + unexpected key + bad pattern all flag
        self.assertTrue(sv.validate({"nope": 1, "id": "X"}, s))
        # lenient: extra key + missing required tolerated; pattern not enforced
        self.assertEqual(sv.validate({"nope": 1}, s, lenient=True), [])
        self.assertEqual(sv.validate({"id": "no-prefix"}, s, lenient=True), [])
        # lenient STILL catches a present wrong type
        self.assertTrue(sv.validate({"id": 7}, s, lenient=True))


# --------------------------------------------------------------------------- #
class TestNewSchemas(unittest.TestCase):
    def test_files_exist_and_valid_json(self):
        for name in NEW_SCHEMAS:
            p = CONTRACT / name
            self.assertTrue(p.is_file(), f"{name} must exist")
            json.loads(p.read_text(encoding="utf-8"))  # raises if invalid

    def test_js_streams_lock_canonical_names(self):
        """Each js stream $def is additionalProperties:false with the identity key required."""
        js = json.loads((CONTRACT / "js_findings.schema.json").read_text(encoding="utf-8"))
        wants = {"endpoint": "url", "param": "name", "api": "api",
                 "secret": "type", "gadget": "sink", "library": "name"}
        for dn, key in wants.items():
            d = js["$defs"][dn]
            self.assertFalse(d["additionalProperties"], f"{dn} must be additionalProperties:false")
            self.assertIn(key, d["required"], f"{dn} must require identity key '{key}'")
        # the canonical fields are declared (NOT the drifted aliases)
        self.assertIn("context", js["$defs"]["param"]["properties"])
        self.assertIn("provider_meta", js["$defs"]["secret"]["properties"])
        self.assertIn("snippet", js["$defs"]["gadget"]["properties"])
        self.assertNotIn("provider", js["$defs"]["secret"]["properties"])

    def test_content_schema_is_tolerant(self):
        cj = json.loads((CONTRACT / "content.schema.json").read_text(encoding="utf-8"))
        self.assertTrue(cj.get("additionalProperties", True))
        self.assertNotIn("required", cj)


# --------------------------------------------------------------------------- #
class TestValidateJsRecon(unittest.TestCase):
    def test_canonical_rows_clean(self):
        payload = {"sites": [{
            "site": "ex.com",
            "libraries": [{"name": "next", "version": "15", "cves": []}],
            "secrets": [{"type": "api-key", "provider_meta": "aws", "match_redacted": "AKIA***"}],
            "params": [{"name": "q", "context": "search", "kind": "query"}],
            "gadgets": [{"sink": "innerHTML", "snippet": "x", "category": "dom"}],
            "endpoints": [{"url": "/api/me", "method": "GET"}],
            "apis": [{"api": "/api/*", "ops": ["list"]}],
        }], "totals": {}, "site_count": 1}
        out = c._validate("js_recon.json", payload)
        self.assertEqual(out["_contract_violations"], [])

    def test_catches_the_drift_and_keeps_the_row(self):
        # the exact regression: `library` instead of `name`, `provider` instead of `provider_meta`,
        # `note` on a param (canonical is `context`), `count` on a gadget (canonical is `snippet`)
        payload = {"sites": [{
            "site": "ex.com",
            "libraries": [{"library": "next", "version": "15"}],
            "secrets": [{"type": "api-key", "provider": "aws"}],
            "params": [{"name": "q", "note": "search"}],
            "gadgets": [{"sink": "eval", "count": 3}],
        }]}
        out = c._validate("js_recon.json", payload)
        paths = {v["path"] for v in out["_contract_violations"]}
        # missing canonical identity key (library row has no `name`)
        self.assertIn("sites[0].libraries[0].name", paths)
        # drifted alias keys surfaced as unexpected properties
        self.assertTrue(any(".library" in p for p in paths))
        self.assertTrue(any(".provider" == p.rsplit("sites[0].secrets[0]", 1)[-1] or ".provider" in p for p in paths))
        self.assertTrue(any(".note" in p for p in paths))
        self.assertTrue(any(".count" in p for p in paths))
        # DEGRADED, NOT BLANK: the rows are still served so the view renders
        self.assertEqual(len(out["sites"][0]["libraries"]), 1)
        self.assertEqual(len(out["sites"][0]["gadgets"]), 1)

    def test_non_dict_row_dropped(self):
        payload = {"sites": [{"site": "ex.com", "libraries": [{"name": "ok"}, "garbage", 5]}]}
        out = c._validate("js_recon.json", payload)
        self.assertEqual(len(out["sites"][0]["libraries"]), 1)   # two bad rows dropped
        self.assertTrue(out["_contract_violations"])

    def test_end_to_end_via_js_recon_report(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            fdir = eng / "js-analysis" / "out" / "ex.com" / "findings"
            fdir.mkdir(parents=True)
            (fdir / "libraries.jsonl").write_text(
                json.dumps({"name": "next", "version": "15", "cves": []}) + "\n"
                + json.dumps({"library": "drifted"}) + "\n", encoding="utf-8")
            out = c._validate("js_recon.json", c.js_recon_report(eng))
            self.assertEqual(out["site_count"], 1)
            self.assertTrue(any("libraries[1]" in v["path"] for v in out["_contract_violations"]))


# --------------------------------------------------------------------------- #
class TestValidateFindings(unittest.TestCase):
    def _finding(self, **over):
        f = {"id": "RS-2026-001", "title": "title", "asset": "https://app.acme.com",
             "category": {}, "severity": "high", "confidence": "confirmed",
             "status": "verified", "evidence": [{"type": "log", "ref": "x"}],
             "reproduction": ["step"]}
        f.update(over)
        return f

    def test_bare_array_normalized_and_clean(self):
        out = c._validate("findings_consolidated.json", [self._finding()])
        self.assertIsInstance(out, dict)
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["_contract_violations"], [])

    def test_object_envelope_keys_preserved(self):
        raw = {"target": "acme.com", "generated": "t", "findings": [self._finding()],
               "attack_chains": [{"id": "chain-001"}]}
        out = c._validate("findings_consolidated.json", raw)
        self.assertEqual(out["target"], "acme.com")              # header preserved
        self.assertEqual(out["attack_chains"], [{"id": "chain-001"}])
        self.assertEqual(out["_contract_violations"], [])

    def test_bad_finding_field_flagged_row_kept(self):
        out = c._validate("findings_consolidated.json", [self._finding(severity="nope")])
        self.assertEqual(len(out["findings"]), 1)                # kept (degraded, not blank)
        self.assertTrue(any("severity" in v["path"] for v in out["_contract_violations"]))

    def test_non_dict_finding_dropped(self):
        out = c._validate("findings_consolidated.json", [self._finding(), "oops", None])
        self.assertEqual(len(out["findings"]), 1)
        self.assertTrue(out["_contract_violations"])


# --------------------------------------------------------------------------- #
class TestValidateHistoryAndContent(unittest.TestCase):
    def test_legacy_flat_array_normalized(self):
        out = c._validate("http_history.json", [{"host": "a", "method": "GET", "path": "/x"}])
        self.assertIn("exchanges", out)
        self.assertEqual(len(out["exchanges"]), 1)
        self.assertEqual(out["_contract_violations"], [])

    def test_bad_exchange_dropped(self):
        out = c._validate("http_history.json", {"exchanges": [{"path": "/ok"}, "garbage"]})
        self.assertEqual(len(out["exchanges"]), 1)
        self.assertTrue(out["_contract_violations"])

    def test_content_tolerant_but_types_checked(self):
        # real-world content.json shape (not the console's canonical keys) still validates clean
        real = {"engagement": "x", "method": "crawl", "counts": {"a": 1},
                "pages_sample": ["/"], "api_endpoints": {"public_200": ["/api/x"]}}
        self.assertEqual(c._validate("content.json", real)["_contract_violations"], [])
        # a canonical field drifted to the wrong type IS caught
        bad = c._validate("content.json", {"routes": "not-a-list"})
        self.assertTrue(any(v["path"] == "routes" for v in bad["_contract_violations"]))


# --------------------------------------------------------------------------- #
class TestValidateExistingSchemasLenient(unittest.TestCase):
    def test_cve_intel_wrong_types_caught_extras_tolerated(self):
        doc = {"target": "t", "generated_at": "2026-01-01T00:00:00Z",
               "summary": "an extra key the schema doesn't declare",   # tolerated (lenient)
               "cves": [{"id": "RSC-1", "component": "Next.js", "cve": "CVE-2025-29927",
                         "source": "nvd",     # WRONG: should be an array
                         "epss": 2.0,         # WRONG: out of 0..1
                         "reachable": "no"}]}
        out = c._validate("cve_intel.json", doc)
        paths = {v["path"] for v in out["_contract_violations"]}
        self.assertIn("cves[0].source", paths)   # type array expected
        self.assertIn("cves[0].epss", paths)      # range 0..1
        # the non-schema `summary` key and the RSC-1 id pattern are NOT flagged (lenient)
        self.assertFalse(any(p == "summary" for p in paths))
        self.assertFalse(any("id" in p for p in paths))

    def test_cve_intel_clean(self):
        doc = {"target": "t", "generated_at": "2026-01-01T00:00:00Z",
               "cves": [{"component": "c", "cve": "CVE-2025-1", "source": ["nvd"],
                         "epss": 0.85, "reachable": "no", "kev": True}]}
        self.assertEqual(c._validate("cve_intel.json", doc)["_contract_violations"], [])

    def test_diagnostics_tolerates_unknown_fields(self):
        # its schema is being extended concurrently -> unknown/optional fields must not flag
        doc = {"engagement": "x", "generated_at": "t", "runs": [],
               "a_future_field": {"nested": [1, 2, 3]}}
        self.assertEqual(c._validate("diagnostics.json", doc)["_contract_violations"], [])

    def test_scope_projection_clean(self):
        proj = c.scope_yaml_to_json  # sanity: shape produced by the console validates clean
        doc = {"engagement": "x", "target": "t", "authorized_by": "a",
               "window": {"start": "s", "end": "e"},
               "in_scope": {"domains": ["x.com"], "cidrs": [], "urls": []},
               "out_of_scope": {"domains": [], "cidrs": [], "urls": []},
               "rules": {}, "notes": "", "source": "scope.yaml"}
        self.assertEqual(c._validate("scope.json", doc)["_contract_violations"], [])
        self.assertTrue(callable(proj))

    def test_unknown_artifact_passes_through(self):
        obj = {"whatever": 1}
        self.assertIs(c._validate("not_a_known_artifact.json", obj), obj)


if __name__ == "__main__":
    unittest.main()
