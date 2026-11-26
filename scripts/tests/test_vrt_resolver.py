#!/usr/bin/env python3
"""
Unit tests for the VRT governance core -- the deterministic CWE/class -> VRT crosswalk + resolver
(scripts/vrt.py) and the report-time VRT HARD gate (skills/_contract/verify_completion.py). This is the
second half of the fix for the fabricated-VRT incident: a FABRICATED VRT category once shipped in a
bug-bounty submission; the structural validator (scripts/validate.py) caught the shape, and this layer
makes a VRT RESOLVED (not improvised) and makes an accepted bug-bounty finding with no / a fabricated /
an inflated VRT impossible to ship silently.

Core guarantees exercised here:
  * resolve_finding_vrt() returns the right real path + taxonomy baseline priority for sample CWEs AND
    executor class slugs, prefers the class slug over the CWE, and returns None for an unmapped key;
  * path_exists() is True for a real id-path / display-name path / leaf id and False for a fabricated one;
  * elevation_errors() flags a P-number stronger than baseline without an argued rationale (anti-
    inflation), passes an argued elevation WITH a rationale, and rejects a fabricated path;
  * the verify_completion VRT-governance gate HARD-FAILS a bug-bounty (program.taxonomy=vrt) engagement
    whose accepted in-scope finding lacks or fabricates its VRT, PASSES a valid one, and is a complete
    NO-OP for a non-program (ordinary pentest) engagement.

Both modules guard their top-level/CLI behaviour behind `if __name__ == "__main__"`, so importing them
here binds only the pure helpers. Stdlib only, runnable as `python test_vrt_resolver.py` (CI convention).
"""
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
REPO = HERE.parents[2]
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(REPO / "skills" / "_contract"))

import vrt  # noqa: E402
import verify_completion as vc  # noqa: E402


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
PROG_SCOPE = """engagement: "bb-2026"
authorized_by: sec@acme / auth-1
program:
  platform: bugcrowd
  name: "acme-bb"
  taxonomy: vrt
in_scope:
  domains:
    - "*.acme.com"
"""

NONE_SCOPE = """engagement: "pt-2026"
authorized_by: sec@acme / auth-1
program:
  platform: none
  taxonomy: none
in_scope:
  domains:
    - "*.acme.com"
"""

GOOD_VRT = {"path": "cross_site_scripting_xss > reflected > non_self", "id": "non_self",
            "priority": "P3", "priority_basis": "baseline"}


def finding(**over) -> dict:
    f = {"id": "RS-2026-010", "title": "Reflected XSS in search", "asset": "https://app.acme.com/s",
         "category": {"owasp": "A03:2021-Injection", "cwe": "CWE-79"}, "severity": "medium",
         "confidence": "confirmed", "status": "verified",
         "evidence": [{"type": "request_response", "ref": "e.txt"}], "reproduction": ["send payload"],
         "review": {"verdict": "accepted", "reviewer": "xss-reflected-verify"}}
    f.update(over)
    return f


def build_engagement(d, scope, f, armed) -> pathlib.Path:
    eng = pathlib.Path(d)
    (eng / "scope.yaml").write_text(scope, encoding="utf-8")
    (eng / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
    if armed:  # a consolidated report present = the engagement is claiming DONE (gates arm)
        (eng / "report").mkdir(parents=True, exist_ok=True)
        (eng / "report" / "findings_consolidated.json").write_text(json.dumps([f]), encoding="utf-8")
    return eng


def gate(scope, f, armed):
    """Run the VRT-governance gate helper against a one-finding engagement; (hard, warns)."""
    with tempfile.TemporaryDirectory() as d:
        eng = build_engagement(d, scope, f, armed)
        findings, _ = vc._discover_engagement_findings(eng)
        return vc._vrt_governance_check(eng, findings, vrt)


# --------------------------------------------------------------------------- #
# path_exists
# --------------------------------------------------------------------------- #
class LoadVrt(unittest.TestCase):
    def test_load_vrt_returns_cached_taxonomy(self):
        tax = vrt.load_vrt()
        self.assertIsInstance(tax, dict)
        self.assertIn("content", tax)
        self.assertIsInstance(tax.get("_meta"), dict)
        self.assertIs(vrt.load_vrt(), tax)  # cached: same object on the second call


class PathExists(unittest.TestCase):
    def test_real_id_path(self):
        self.assertTrue(vrt.path_exists("server_side_injection > sql_injection"))
        self.assertTrue(vrt.path_exists("cross_site_scripting_xss > reflected > non_self"))

    def test_real_display_name_path(self):
        self.assertTrue(vrt.path_exists("Server-Side Injection > SQL Injection"))
        self.assertTrue(vrt.path_exists("Cross-Site Scripting (XSS) > Reflected > Non-Self"))

    def test_bare_leaf_id(self):
        self.assertTrue(vrt.path_exists("sql_injection"))
        self.assertTrue(vrt.path_exists("text_injection"))

    def test_fabricated_path_false(self):
        # the exact shape of the real incident: a category that does not exist.
        self.assertFalse(vrt.path_exists("Broken Access Control / Server-Side Improper Authorization"))
        self.assertFalse(vrt.path_exists("server_side_injection > made_up_node"))
        self.assertFalse(vrt.path_exists("totally_made_up_leaf"))

    def test_empty_false(self):
        self.assertFalse(vrt.path_exists(""))
        self.assertFalse(vrt.path_exists("   "))


# --------------------------------------------------------------------------- #
# resolve_finding_vrt
# --------------------------------------------------------------------------- #
class ResolveFindingVrt(unittest.TestCase):
    def test_cwe_xss(self):
        r = vrt.resolve_finding_vrt(cwe="CWE-79")
        self.assertEqual(r["path"], "cross_site_scripting_xss > reflected > non_self")
        self.assertEqual(r["id"], "non_self")
        self.assertEqual(r["priority"], "P3")
        self.assertEqual(r["baseline"], "P3")

    def test_cwe_number_normalization(self):
        self.assertEqual(vrt.resolve_finding_vrt(cwe="79")["id"], "non_self")
        self.assertEqual(vrt.resolve_finding_vrt(cwe="cwe-89")["path"], "server_side_injection > sql_injection")

    def test_class_sqli(self):
        r = vrt.resolve_finding_vrt(category="sqli-inband")
        self.assertEqual(r["path"], "server_side_injection > sql_injection")
        self.assertEqual(r["priority"], "P1")

    def test_class_idor_default_is_representative_not_maximal(self):
        r = vrt.resolve_finding_vrt(category="idor")
        self.assertEqual(r["id"], "view_sensitive_information_iterable_object_identifiers")
        self.assertEqual(r["priority"], "P3")  # a mid default, NOT the P1 modify variant

    def test_class_preferred_over_cwe(self):
        r = vrt.resolve_finding_vrt(cwe="CWE-89", category="xss-reflected")
        self.assertTrue(r["path"].startswith("cross_site_scripting_xss"))

    def test_candidate_list_returns_primary(self):
        # CWE-918 is a candidate list; the primary is internal_data_exposure (P3).
        r = vrt.resolve_finding_vrt(cwe="CWE-918")
        self.assertEqual(r["id"], "internal_data_exposure")
        self.assertEqual(r["priority"], "P3")

    def test_varies_node_has_none_priority(self):
        r = vrt.resolve_finding_vrt(category="cors")
        self.assertIsNotNone(r)
        self.assertIsNone(r["priority"])
        self.assertIsNone(r["baseline"])

    def test_unmapped_returns_none(self):
        self.assertIsNone(vrt.resolve_finding_vrt(cwe="CWE-0000"))
        self.assertIsNone(vrt.resolve_finding_vrt(category="not-a-real-class"))
        self.assertIsNone(vrt.resolve_finding_vrt())

    def test_every_crosswalk_target_resolves(self):
        """Hard guarantee mirrored by validate.py: no crosswalk entry points at a non-existent node."""
        xw = vrt._load_crosswalk()
        for section in ("cwe", "class"):
            for key, entry in (xw.get(section) or {}).items():
                for cand in vrt._candidates(entry):
                    self.assertTrue(vrt.path_exists(cand["path"]),
                                    f"{section}.{key} -> {cand['path']!r} does not resolve")


# --------------------------------------------------------------------------- #
# elevation_errors
# --------------------------------------------------------------------------- #
class ElevationErrors(unittest.TestCase):
    SSI_TI = "server_side_injection > content_spoofing > text_injection"    # baseline P5 leaf
    SSI_IF = "server_side_injection > content_spoofing > iframe_injection"  # baseline P3 leaf

    def test_baseline_passes(self):
        self.assertEqual(vrt.elevation_errors(self.SSI_TI, "P5", "baseline", None), [])

    def test_stronger_than_baseline_without_rationale_flags(self):
        errs = vrt.elevation_errors(self.SSI_TI, "P3", "baseline", None)
        self.assertTrue(errs)
        self.assertIn("inflation", " ".join(errs).lower())

    def test_default_basis_treated_as_baseline(self):
        self.assertTrue(vrt.elevation_errors(self.SSI_TI, "P3", None, None))

    def test_argued_elevation_without_rationale_flags(self):
        errs = vrt.elevation_errors(self.SSI_TI, "P3", "argued-elevation", None)
        self.assertTrue(errs)
        self.assertIn("rationale", " ".join(errs).lower())

    def test_argued_elevation_with_rationale_passes(self):
        self.assertEqual(
            vrt.elevation_errors(self.SSI_TI, "P3", "argued-elevation",
                                 "demonstrated cross-user nickname spoofing, not plain text injection"), [])

    def test_argued_reduction_with_rationale_passes(self):
        self.assertEqual(
            vrt.elevation_errors(self.SSI_IF, "P5", "argued-reduction", "no sensitive action is framed"), [])

    def test_variant_ceiling_cannot_be_argued_past(self):
        # content_spoofing's most severe real variant is P3 (iframe); claiming P1 is not allowed even argued.
        cs = "server_side_injection > content_spoofing"
        errs = vrt.elevation_errors(cs, "P1", "argued-elevation", "over-rating")
        self.assertTrue(errs)
        self.assertIn("variants allow", " ".join(errs).lower())
        self.assertEqual(vrt.elevation_errors(cs, "P3", "baseline", None), [])  # matches the strongest variant

    def test_fabricated_path_flags(self):
        self.assertTrue(vrt.elevation_errors("not > a > real > path", "P3", "baseline", None))

    def test_none_priority_is_not_a_claim(self):
        self.assertEqual(vrt.elevation_errors(self.SSI_TI, None, "baseline", None), [])

    def test_bad_priority_token_flags(self):
        self.assertTrue(vrt.elevation_errors(self.SSI_TI, "P9", "baseline", None))


# --------------------------------------------------------------------------- #
# the verify_completion VRT-governance HARD gate
# --------------------------------------------------------------------------- #
class VrtGovernanceGate(unittest.TestCase):
    def test_vrt_module_imports(self):
        self.assertIsNotNone(vc._try_import_vrt())

    def test_valid_vrt_passes_even_armed(self):
        hard, warns = gate(PROG_SCOPE, finding(vrt=GOOD_VRT), armed=True)
        self.assertEqual(hard, [])
        self.assertEqual(warns, [])

    def test_missing_vrt_hard_fails_when_armed(self):
        hard, warns = gate(PROG_SCOPE, finding(), armed=True)
        self.assertTrue(hard)
        self.assertIn("no `vrt", " ".join(hard).lower())

    def test_missing_vrt_is_warning_while_hunting(self):
        hard, warns = gate(PROG_SCOPE, finding(), armed=False)
        self.assertEqual(hard, [])
        self.assertTrue(warns)
        self.assertIn("hard gate once a report exists", " ".join(warns).lower())

    def test_fabricated_vrt_hard_fails_when_armed(self):
        bad = {"path": "Broken Access Control / Server-Side Improper Authorization", "priority": "P1"}
        hard, _ = gate(PROG_SCOPE, finding(vrt=bad), armed=True)
        self.assertTrue(hard)
        self.assertIn("does not resolve", " ".join(hard).lower())

    def test_inflated_priority_hard_fails_when_armed(self):
        inflated = {"path": "cross_site_scripting_xss > reflected > non_self",
                    "priority": "P1", "priority_basis": "baseline"}
        hard, _ = gate(PROG_SCOPE, finding(vrt=inflated), armed=True)
        self.assertTrue(hard)
        self.assertIn("inflation", " ".join(hard).lower())

    def test_argued_elevation_with_rationale_passes_when_armed(self):
        argued = {"path": "cross_site_scripting_xss > reflected > non_self", "priority": "P2",
                  "priority_basis": "argued-elevation",
                  "priority_rationale": "demonstrated cross-user execution against an admin viewer"}
        hard, warns = gate(PROG_SCOPE, finding(vrt=argued), armed=True)
        self.assertEqual(hard, [])

    def test_rejected_finding_is_ignored(self):
        f = finding(review={"verdict": "rejected", "reviewer": "xss-reflected-verify"}, status="rejected")
        hard, warns = gate(PROG_SCOPE, f, armed=True)
        self.assertEqual(hard, [])
        self.assertEqual(warns, [])

    def test_out_of_scope_finding_is_ignored(self):
        f = finding(asset="https://evil.example.org/x")  # not in *.acme.com
        hard, warns = gate(PROG_SCOPE, f, armed=True)
        self.assertEqual(hard, [])

    def test_non_program_engagement_is_noop(self):
        # an ordinary pentest (program.platform none): the gate must never fire, even with no VRT + a report.
        hard, warns = gate(NONE_SCOPE, finding(), armed=True)
        self.assertEqual(hard, [])
        self.assertEqual(warns, [])

    def test_composite_finding_is_skipped(self):
        f = finding(composite=True)
        hard, warns = gate(PROG_SCOPE, f, armed=True)
        self.assertEqual(hard, [])


# --------------------------------------------------------------------------- #
# end-to-end wiring through validate_engagement (the --engagement run)
# --------------------------------------------------------------------------- #
class ValidateEngagementWiring(unittest.TestCase):
    def _run_json(self, scope, f, armed):
        with tempfile.TemporaryDirectory() as d:
            eng = build_engagement(d, scope, f, armed)
            buf = io.StringIO()
            with redirect_stdout(buf):
                vc.validate_engagement(eng, as_json=True)
            return json.loads(buf.getvalue())

    def test_bad_bugbounty_engagement_reports_vrt_errors_and_fails(self):
        payload = self._run_json(PROG_SCOPE, finding(), armed=True)  # missing vrt, report present
        self.assertFalse(payload["pass"])
        self.assertTrue(payload["vrt_governance_errors"])

    def test_good_vrt_has_no_vrt_errors(self):
        payload = self._run_json(PROG_SCOPE, finding(vrt=GOOD_VRT), armed=True)
        self.assertEqual(payload["vrt_governance_errors"], [])

    def test_non_program_engagement_has_no_vrt_errors(self):
        payload = self._run_json(NONE_SCOPE, finding(), armed=True)
        self.assertEqual(payload["vrt_governance_errors"], [])


if __name__ == "__main__":
    unittest.main()
