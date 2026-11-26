#!/usr/bin/env python3
"""
Unit tests for scripts/bugcrowd_submission.py -- the bug-bounty submission generator (roadmap L-D).

Guarantees under test (the fix for the fabricated-VRT incident):
  * a program-flagged engagement (scope.yaml program.platform set) with an accepted, in-scope finding
    emits a well-formed submissions/<id>.md carrying the form fields + the STAMPED, validated VRT;
  * a finding whose VRT FAILS validation (fabricated path / inflated priority / unresolvable on bugcrowd)
    is REFUSED with a named error -- nothing is written for it (a bad VRT is structurally un-emittable);
  * a non-program engagement emits NOTHING (byte-identical no-op);
  * hackerone uses a CWE + CVSS headline (VRT optional) while bugcrowd's headline IS the VRT bucket;
  * secrets are redacted and evidence is referenced by path; the generator is idempotent.

The vrt core (scripts/vrt.py) is built IN PARALLEL, so these tests MOCK it with an in-process `FakeVrt`
driven by a tiny taxonomy -- no cross-dependency, runnable before integration. Stdlib only, runnable as
`python test_bugcrowd_submission.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import bugcrowd_submission as bs  # noqa: E402


# ---------------------------------------------------------------------------------------------------
# A mock VRT core matching the interface this module codes against:
#   resolve_finding_vrt(cwe=None, category=None) -> {"path","id","priority","baseline"} | None
#   path_exists(path_or_id) -> bool
#   elevation_errors(path, priority, basis, rationale) -> list[str]
# ---------------------------------------------------------------------------------------------------
class FakeVrt:
    # real taxonomy nodes (path or leaf-id) -> baseline priority
    BASELINES = {
        "cross_site_scripting > stored": 2,
        "stored": 2,
        "server_side_injection > content_spoofing > text_injection": 5,
        "text_injection": 5,
        "server_side_injection > sql_injection": 1,
        "sql_injection": 1,
    }
    # cwe -> resolved vrt dict
    BY_CWE = {
        "CWE-79": {"path": "cross_site_scripting > stored", "id": "stored", "priority": "P2", "baseline": 2},
        "CWE-89": {"path": "server_side_injection > sql_injection", "id": "sql_injection",
                   "priority": "P1", "baseline": 1},
    }
    # category class-name hint -> resolved (fallback when the cwe doesn't map)
    BY_CATEGORY = {
        "xss-stored": {"path": "cross_site_scripting > stored", "id": "stored", "priority": "P2",
                       "baseline": 2},
    }

    def resolve_finding_vrt(self, cwe=None, category=None):
        hit = self.BY_CWE.get(str(cwe or "").upper())
        if hit:
            return dict(hit)
        hit = self.BY_CATEGORY.get(str(category or "").lower())
        return dict(hit) if hit else None

    def path_exists(self, ref):
        return str(ref).strip().lower() in {k.lower() for k in self.BASELINES}

    def elevation_errors(self, path, priority, basis, rationale):
        base = self.BASELINES.get(str(path).strip().lower())
        pr = bs._p_str(priority)
        claimed = int(pr[1:]) if pr else None
        if claimed is not None and base is not None and claimed < base:  # lower P = stronger
            if basis != "argued-elevation":
                return [f"priority {pr} stronger than baseline P{base} without argued-elevation"]
            if not str(rationale or "").strip():
                return ["argued-elevation requires a non-empty priority_rationale"]
        return []


def F(fid="RS-2026-001", cwe="CWE-79", asset="https://app.example.com/p", sev="high",
      verdict="accepted", status="verified", reviewer="xss-stored-verify", **over):
    f = {"id": fid, "title": f"Stored XSS in {fid}", "asset": asset,
         "category": {"cwe": cwe, "owasp": "A03"}, "severity": sev, "status": status,
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
         "impact": "runs in a victim session", "remediation": "encode output",
         "evidence": [{"type": "request_response", "ref": "poc/x.http", "sha256": "a" * 64}],
         "reproduction": ["GET /p", "observe alert"],
         "review": {"verdict": verdict, "reviewer": reviewer}}
    f.update(over)
    return f


SCOPE_BUGCROWD = ("engagement: t\nprogram:\n  platform: bugcrowd\n  name: acme\n"
                  "  url: https://bugcrowd.com/acme\n  taxonomy: vrt\n"
                  "in_scope:\n  domains:\n    - '*.example.com'\n"
                  "out_of_scope:\n  domains:\n    - admin.example.com\n")
SCOPE_HACKERONE = ("engagement: t\nprogram:\n  platform: hackerone\n  name: acme-h1\n  taxonomy: vrt\n"
                   "in_scope:\n  domains:\n    - '*.example.com'\n")
SCOPE_PENTEST = "engagement: t\nprogram:\n  platform: none\n  taxonomy: none\n"


def _mk_engagement(td, scope_text, findings):
    eng = pathlib.Path(td) / "eng"
    (eng / "report").mkdir(parents=True)
    (eng / "scope.yaml").write_text(scope_text, encoding="utf-8")
    (eng / "report" / "findings_consolidated.json").write_text(json.dumps(findings), encoding="utf-8")
    return eng


class ProgramDetection(unittest.TestCase):
    def test_program_block_parsed_from_minimal_yaml(self):
        scope = bs._minimal_scope_read(SCOPE_BUGCROWD)
        prog = bs.program_of(scope)
        self.assertEqual(prog.get("platform"), "bugcrowd")
        self.assertEqual(prog.get("name"), "acme")
        self.assertEqual(prog.get("taxonomy"), "vrt")

    def test_platform_of(self):
        self.assertEqual(bs.platform_of({"platform": "bugcrowd"}), "bugcrowd")
        self.assertEqual(bs.platform_of({"platform": "hackerone"}), "hackerone")
        self.assertEqual(bs.platform_of({"platform": "none"}), "")
        self.assertEqual(bs.platform_of({}), "")
        self.assertEqual(bs.platform_of({"platform": "nope"}), "")


class ScopeMatching(unittest.TestCase):
    def setUp(self):
        self.scope = {"in_scope": {"domains": ["*.example.com", "api.foo.com"]},
                      "out_of_scope": {"domains": ["admin.example.com"]}}

    def test_wildcard_in_scope(self):
        self.assertTrue(bs.asset_in_scope("https://app.example.com/x", self.scope))
        self.assertTrue(bs.asset_in_scope("https://example.com/x", self.scope))

    def test_out_of_scope_wins(self):
        self.assertFalse(bs.asset_in_scope("https://admin.example.com/x", self.scope))

    def test_not_in_scope(self):
        self.assertFalse(bs.asset_in_scope("https://evil.test/x", self.scope))

    def test_exact_url_host(self):
        self.assertTrue(bs.asset_in_scope("https://api.foo.com:443/v1", self.scope))

    def test_no_in_scope_means_include(self):
        self.assertTrue(bs.asset_in_scope("https://whatever.test/x", {}))


class Redaction(unittest.TestCase):
    def test_bearer_masked(self):
        self.assertIn("<redacted>", bs.redact("Authorization: Bearer eyJhbGciOi.ABCDEFGH.sig"))
        self.assertNotIn("eyJhbGciOi.ABCDEFGH.sig", bs.redact("Bearer eyJhbGciOi.ABCDEFGH.sig"))

    def test_kv_secret_masked(self):
        self.assertTrue(bs.redact("api_key=SECRETVALUE123").endswith("<redacted>"))
        self.assertIn("<redacted>", bs.redact("password: hunter2hunter"))

    def test_prose_survives(self):
        self.assertEqual(bs.redact("the token in the URL is reflected"),
                         "the token in the URL is reflected")

    def test_empty(self):
        self.assertEqual(bs.redact(""), "")
        self.assertEqual(bs.redact(None), "")


class ReportableFilter(unittest.TestCase):
    def test_accepted_and_blocked_in_rest_out(self):
        self.assertTrue(bs.is_reportable(F(verdict="accepted")))
        self.assertTrue(bs.is_reportable(F(verdict="blocked")))
        self.assertFalse(bs.is_reportable(F(verdict="rejected", status="rejected")))
        self.assertFalse(bs.is_reportable(F(verdict="needs-evidence", status="open")))
        self.assertFalse(bs.is_reportable(F(verdict="accepted", status="duplicate")))
        self.assertFalse(bs.is_reportable(F(verdict="accepted", composite=True)))

    def test_verified_status_without_review(self):
        f = F()
        del f["review"]
        self.assertTrue(bs.is_reportable(f))
        f["status"] = "open"
        self.assertFalse(bs.is_reportable(f))


class VrtStamping(unittest.TestCase):
    def setUp(self):
        self.vrt = FakeVrt()

    def test_resolved_from_cwe_bugcrowd(self):
        info = bs.resolve_submission_vrt(F(), "bugcrowd", vrt=self.vrt)
        self.assertEqual(info["path"], "cross_site_scripting > stored")
        self.assertEqual(info["priority"], "P2")
        self.assertEqual(info["source"], "resolved")

    def test_authored_valid_block_passes(self):
        f = F(vrt={"path": "server_side_injection > content_spoofing > text_injection",
                   "priority": "P3", "priority_basis": "argued-elevation",
                   "priority_rationale": "demonstrated cross-user nickname spoofing"})
        info = bs.resolve_submission_vrt(f, "bugcrowd", vrt=self.vrt)
        self.assertEqual(info["source"], "authored")
        self.assertEqual(info["priority"], "P3")

    def test_authored_fabricated_path_refused(self):
        f = F(vrt={"path": "Broken Access Control / Totally Made Up", "priority": "P1"})
        with self.assertRaises(bs._Refused) as cm:
            bs.resolve_submission_vrt(f, "bugcrowd", vrt=self.vrt)
        self.assertIn("fabricated", str(cm.exception).lower())

    def test_authored_inflated_priority_refused(self):
        # P3 on a P5-baseline path, basis=baseline -> inflation.
        f = F(vrt={"path": "server_side_injection > content_spoofing > text_injection",
                   "priority": "P3", "priority_basis": "baseline"})
        with self.assertRaises(bs._Refused) as cm:
            bs.resolve_submission_vrt(f, "bugcrowd", vrt=self.vrt)
        self.assertIn("baseline", str(cm.exception).lower())

    def test_bugcrowd_unresolvable_cwe_refused(self):
        f = F(cwe="CWE-0000", reviewer="mystery-verify")  # neither cwe nor category hint maps
        with self.assertRaises(bs._Refused) as cm:
            bs.resolve_submission_vrt(f, "bugcrowd", vrt=self.vrt)
        self.assertIn("bugcrowd requires", str(cm.exception).lower())

    def test_hackerone_unresolvable_cwe_omits_vrt(self):
        f = F(cwe="CWE-0000", reviewer="mystery-verify")
        self.assertIsNone(bs.resolve_submission_vrt(f, "hackerone", vrt=self.vrt))

    def test_category_hint_fallback_resolves(self):
        # cwe doesn't map, but the reviewer-derived class hint (xss-stored) does.
        f = F(cwe="CWE-0000", reviewer="xss-stored-verify")
        info = bs.resolve_submission_vrt(f, "bugcrowd", vrt=self.vrt)
        self.assertEqual(info["path"], "cross_site_scripting > stored")


class GenerateEndToEnd(unittest.TestCase):
    def setUp(self):
        self.vrt = FakeVrt()

    def test_program_engagement_writes_well_formed_submission(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [F("RS-2026-001")])
            res = bs.generate(eng, vrt=self.vrt)
            self.assertEqual([w["id"] for w in res["written"]], ["RS-2026-001"])
            self.assertEqual(res["refused"], [])
            md = (eng / "submissions" / "RS-2026-001.md").read_text(encoding="utf-8")
            for field in ("## Submission form", "Title / Summary", "Target / Asset",
                          "Technical severity", "## Vulnerability details", "### Steps to reproduce",
                          "### Impact", "### Remediation", "### Proof / evidence"):
                self.assertIn(field, md)
            self.assertIn("`cross_site_scripting > stored`", md)   # the stamped VRT
            self.assertIn("P2", md)
            self.assertIn("poc/x.http", md)                        # evidence by path
            self.assertNotIn("a" * 64, md)                         # full sha not inlined (fingerprint only)

    def test_failed_vrt_refused_nothing_written(self):
        with tempfile.TemporaryDirectory() as td:
            bad = F("RS-2026-002", vrt={"path": "Made Up > Nope", "priority": "P1"})
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [F("RS-2026-001"), bad])
            res = bs.generate(eng, vrt=self.vrt)
            self.assertEqual([w["id"] for w in res["written"]], ["RS-2026-001"])
            self.assertEqual([r["id"] for r in res["refused"]], ["RS-2026-002"])
            self.assertIn("fabricated", res["refused"][0]["reason"].lower())
            self.assertFalse((eng / "submissions" / "RS-2026-002.md").exists())
            self.assertTrue((eng / "submissions" / "RS-2026-001.md").is_file())

    def test_non_program_engagement_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_PENTEST, [F("RS-2026-001")])
            res = bs.generate(eng, vrt=self.vrt)
            self.assertFalse(res["is_program"])
            self.assertEqual(res["written"], [])
            self.assertFalse((eng / "submissions").exists())

    def test_hackerone_headline_is_cwe_cvss(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_HACKERONE, [F("RS-2026-001")])
            res = bs.generate(eng, vrt=self.vrt)
            self.assertEqual([w["id"] for w in res["written"]], ["RS-2026-001"])
            md = (eng / "submissions" / "RS-2026-001.md").read_text(encoding="utf-8")
            self.assertIn("**Weakness:** CWE-79", md)
            self.assertIn("**CVSS:**", md)
            self.assertIn("VRT (supplementary)", md)

    def test_hackerone_unresolvable_still_writes_without_vrt(self):
        with tempfile.TemporaryDirectory() as td:
            f = F("RS-2026-009", cwe="CWE-0000", reviewer="mystery-verify")
            eng = _mk_engagement(td, SCOPE_HACKERONE, [f])
            res = bs.generate(eng, vrt=self.vrt)
            self.assertEqual([w["id"] for w in res["written"]], ["RS-2026-009"])
            md = (eng / "submissions" / "RS-2026-009.md").read_text(encoding="utf-8")
            self.assertNotIn("VRT (supplementary)", md)

    def test_out_of_scope_finding_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            oos = F("RS-2026-003", asset="https://admin.example.com/secret")
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [oos])
            res = bs.generate(eng, vrt=self.vrt)
            self.assertEqual(res["written"], [])
            self.assertEqual(res["skipped_scope"], ["RS-2026-003"])
            self.assertFalse((eng / "submissions" / "RS-2026-003.md").exists())

    def test_duplicate_and_composite_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            findings = [F("RS-2026-001"),
                        F("RS-2026-002", status="duplicate"),
                        F("RS-2026-003", composite=True)]
            eng = _mk_engagement(td, SCOPE_BUGCROWD, findings)
            res = bs.generate(eng, vrt=self.vrt)
            self.assertEqual([w["id"] for w in res["written"]], ["RS-2026-001"])

    def test_idempotent_rerun_identical(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [F("RS-2026-001")])
            bs.generate(eng, vrt=self.vrt)
            first = (eng / "submissions" / "RS-2026-001.md").read_text(encoding="utf-8")
            bs.generate(eng, vrt=self.vrt)
            second = (eng / "submissions" / "RS-2026-001.md").read_text(encoding="utf-8")
            self.assertEqual(first, second)

    def test_bearer_token_redacted_in_submission(self):
        with tempfile.TemporaryDirectory() as td:
            f = F("RS-2026-001", impact="leak via Authorization: Bearer eyJsecretAAA.BBB.CCC token")
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [f])
            bs.generate(eng, vrt=self.vrt)
            md = (eng / "submissions" / "RS-2026-001.md").read_text(encoding="utf-8")
            self.assertIn("<redacted>", md)
            self.assertNotIn("eyJsecretAAA.BBB.CCC", md)


class GuardAndCli(unittest.TestCase):
    def test_require_vrt_raises_when_core_absent(self):
        with mock.patch.object(bs, "vrt_core", None):
            with self.assertRaises(RuntimeError) as cm:
                bs._require_vrt()
            self.assertIn("vrt", str(cm.exception).lower())

    def test_generate_program_without_core_raises(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [F("RS-2026-001")])
            with mock.patch.object(bs, "vrt_core", None):
                with self.assertRaises(RuntimeError):
                    bs.generate(eng)  # no vrt passed -> falls back to the (absent) core

    def test_generate_nonprogram_without_core_is_safe_noop(self):
        # a non-program engagement must NOT require the vrt core at all.
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_PENTEST, [F("RS-2026-001")])
            with mock.patch.object(bs, "vrt_core", None):
                res = bs.generate(eng)
            self.assertFalse(res["is_program"])

    def test_cli_returns_3_on_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            bad = F("RS-2026-002", vrt={"path": "Made Up > Nope", "priority": "P1"})
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [bad])
            with mock.patch.object(bs, "vrt_core", FakeVrt()):
                rc = bs.main(["--engagement", str(eng), "--quiet"])
            self.assertEqual(rc, 3)

    def test_cli_returns_2_when_core_absent(self):
        with tempfile.TemporaryDirectory() as td:
            eng = _mk_engagement(td, SCOPE_BUGCROWD, [F("RS-2026-001")])
            with mock.patch.object(bs, "vrt_core", None):
                rc = bs.main(["--engagement", str(eng), "--quiet"])
            self.assertEqual(rc, 2)

    def test_cli_selftest_green(self):
        self.assertEqual(bs.main(["--selftest"]), 0)


class EmbeddedSelfTest(unittest.TestCase):
    def test_module_selftest_green(self):
        self.assertEqual(bs.selftest(), 0)


if __name__ == "__main__":
    unittest.main()
