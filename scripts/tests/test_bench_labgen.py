#!/usr/bin/env python3
"""
Unit tests for scripts/bench_labgen.py -- the CVE-KB-seeded LABELED-LAB generator -- and the
scripts/benchmark.py --score-labs integration that scores a run against those self-labeling labs.

Guarantees locked here:
  * version pinning from an affected_range is deterministic (exact / >= / <= pin; strict-only / empty skip),
  * a lab-able row emits docker-compose.yml + answer_key.json + README.md, and the answer_key VALIDATES
    against skills/_contract/bench_label.schema.json,
  * the HONESTY GUARD holds: every generated answer_key is boot_status='unverified' (the generator never
    emits 'verified'), and the scorer counts ONLY verified labs -- so an un-booted scaffold can never
    fabricate a measured number,
  * non-lab-able rows are SKIPPED with a reason (not emitted as broken labs),
  * app-image vs library-runtime compose scaffolds are chosen by ecosystem, and the planted CVE maps to a
    true positive (recall) while an unmatched finding stays an FP *candidate* (never auto-failed).

CI runs each scripts/tests/test_*.py standalone under `bash -e -o pipefail`; the Windows runner uses 8.3
short tempdir names, so any absolute-path substring comparison .resolve()s the expected path. Stdlib only,
runnable as `python test_bench_labgen.py`.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
REPO = HERE.parents[2]
sys.path.insert(0, str(SCRIPTS))

import bench_labgen as lg  # noqa: E402
import benchmark as bm  # noqa: E402
import structvalidate as sv  # noqa: E402

SCHEMA = json.loads((REPO / "skills" / "_contract" / "bench_label.schema.json").read_text(encoding="utf-8"))


def kb(cve="CVE-2024-11111", component="wordpress", ecosystem="generic", affected_range="=6.4.2", **over):
    r = {"cve_id": cve, "component": component, "ecosystem": ecosystem, "affected_range": affected_range,
         "cwe": "CWE-79", "technique_class": "xss"}
    r.update(over)
    return r


class VersionPinning(unittest.TestCase):
    def test_exact_lower_upper_bounds_pin(self):
        self.assertEqual(lg.pin_from_range("=1.4.1"), "1.4.1")
        self.assertEqual(lg.pin_from_range("==1.4.1"), "1.4.1")
        self.assertEqual(lg.pin_from_range(">=2.0.0 <2.6.3"), "2.0.0")
        self.assertEqual(lg.pin_from_range("<=1.2.3"), "1.2.3")

    def test_strict_only_or_empty_is_unpinnable(self):
        self.assertEqual(lg.pin_from_range("<3.4.0"), "")
        self.assertEqual(lg.pin_from_range(">2.0.0"), "")
        self.assertEqual(lg.pin_from_range(""), "")
        self.assertEqual(lg.pin_from_range(None), "")

    def test_plain_version_field_wins_over_range(self):
        self.assertEqual(lg.pin_version({"version": "6.4.2"}), "6.4.2")
        # a version field carrying an operator is NOT plain -> fall through to the range
        self.assertEqual(lg.pin_version({"version": "<3.4.0", "affected_range": "=9.9.9"}), "9.9.9")


class Normalization(unittest.TestCase):
    def test_cwe_and_cve_normalization(self):
        self.assertEqual(lg._norm_cwe("1321"), "CWE-1321")
        self.assertEqual(lg._norm_cwe("cwe-79"), "CWE-79")
        self.assertEqual(lg._norm_cwe("junk"), "")
        self.assertEqual(lg._norm_cve("cve-2024-1234"), "CVE-2024-1234")
        self.assertEqual(lg._norm_cve("not-a-cve"), "")

    def test_matcher_priority_cwe_owasp_class(self):
        self.assertEqual(lg.build_matcher({"cwe": "CWE-79"}), {"cwe": "CWE-79"})
        self.assertEqual(lg.build_matcher({"owasp": "A03"}), {"owasp": "A03"})
        m = lg.build_matcher({"vuln_class": "prototype-pollution"})
        self.assertIn("title_regex", m)
        import re
        self.assertTrue(re.search(m["title_regex"], "Prototype Pollution found", re.I))
        self.assertEqual(lg.build_matcher({}), {})


class Generation(unittest.TestCase):
    def test_emits_three_files_and_answer_key_validates(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "labs"
            rep = lg.labgen([lg.normalize_kb_row(kb())], out, generated_at="2026-01-01T00:00:00Z")
            self.assertEqual(rep["counts"]["emitted"], 1)
            lab = out / "wordpress-6.4.2-cve-2024-11111"
            self.assertTrue((lab / "docker-compose.yml").is_file())
            self.assertTrue((lab / "answer_key.json").is_file())
            self.assertTrue((lab / "README.md").is_file())
            ak = json.loads((lab / "answer_key.json").read_text(encoding="utf-8"))
            self.assertEqual(sv.validate(ak, SCHEMA), [])  # STRICT schema conformance

    def test_honesty_guard_never_verified(self):
        rows = [lg.normalize_kb_row(kb()),
                lg.normalize_kb_row(kb(cve="CVE-2023-22222", component="lodash", ecosystem="npm",
                                       affected_range=">=4.0.0 <4.17.21", cwe="CWE-1321",
                                       technique_class="prototype-pollution"))]
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "labs"
            rep = lg.labgen(rows, out, generated_at="2026-01-01T00:00:00Z")
            for e in rep["emitted"]:
                self.assertEqual(e["boot_status"], "unverified")
                ak = json.loads((out / e["slug"] / "answer_key.json").read_text(encoding="utf-8"))
                self.assertEqual(ak["boot_status"], "unverified")

    def test_app_image_and_backing_db(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "labs"
            lg.labgen([lg.normalize_kb_row(kb())], out, generated_at="t")
            compose = (out / "wordpress-6.4.2-cve-2024-11111" / "docker-compose.yml").read_text(
                encoding="utf-8")
        self.assertIn("image: wordpress:6.4.2", compose)   # target-descriptive fact from the CVE data
        self.assertIn("mariadb:11", compose)               # minimal backing db the component implies
        self.assertIn("depends_on", compose)

    def test_library_runtime_scaffold_not_a_bogus_image(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "labs"
            lg.labgen([lg.normalize_kb_row(kb(cve="CVE-2023-22222", component="lodash", ecosystem="npm",
                                               affected_range="=4.17.20", cwe="CWE-1321"))], out,
                      generated_at="t")
            compose = (out / "lodash-4.17.20-cve-2023-22222" / "docker-compose.yml").read_text(
                encoding="utf-8")
        self.assertIn("image: node:lts", compose)
        self.assertIn("npm install lodash@4.17.20", compose)
        self.assertNotIn("image: lodash:", compose)  # NOT a non-existent package-as-image

    def test_determinism(self):
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "a"
            b = pathlib.Path(d) / "b"
            lg.labgen([lg.normalize_kb_row(kb())], a, generated_at="2026-01-01T00:00:00Z")
            lg.labgen([lg.normalize_kb_row(kb())], b, generated_at="2026-01-01T00:00:00Z")
            slug = "wordpress-6.4.2-cve-2024-11111"
            self.assertEqual((a / slug / "answer_key.json").read_text(encoding="utf-8"),
                             (b / slug / "answer_key.json").read_text(encoding="utf-8"))
            self.assertEqual((a / slug / "docker-compose.yml").read_text(encoding="utf-8"),
                             (b / slug / "docker-compose.yml").read_text(encoding="utf-8"))

    def test_out_dir_path_resolves_on_windows_short_names(self):
        # 8.3 short tempdir guard: compare resolved paths, never a raw substring.
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "labs"
            rep = lg.labgen([lg.normalize_kb_row(kb())], out, generated_at="t")
            self.assertEqual(pathlib.Path(rep["out_dir"]).resolve(), out.resolve())


class Skipping(unittest.TestCase):
    def test_skip_reasons_recorded_not_emitted(self):
        rows = [
            lg.normalize_kb_row(kb(cve="CVE-2022-33333", component="jquery", ecosystem="npm",
                                   affected_range="<3.5.0")),                         # unpinnable
            lg.normalize_kb_row(kb(cve="CVE-2021-44444", component="openssl", ecosystem="os",
                                   affected_range="=1.1.1", cwe=None, technique_class=None)),  # no class
            lg.normalize_kb_row(kb(cve="CVE-2020-55555", component="Some.Pkg", ecosystem="nuget",
                                   affected_range="=12.0.1", cwe="CWE-502")),          # unsupported ecosystem
            lg.normalize_kb_row(kb(cve="not-a-cve")),                                  # bad cve id
        ]
        with tempfile.TemporaryDirectory() as d:
            rep = lg.labgen(rows, pathlib.Path(d) / "labs", generated_at="t", write=False)
        self.assertEqual(rep["counts"]["emitted"], 0)
        reasons = sorted(s["reason"] for s in rep["skipped"])
        self.assertEqual(reasons, ["missing-or-invalid-cve-id", "no-weakness-class",
                                   "unpinnable-version", "unsupported-ecosystem:nuget"])

    def test_duplicate_slug_skipped_once(self):
        rows = [lg.normalize_kb_row(kb()), lg.normalize_kb_row(kb())]
        with tempfile.TemporaryDirectory() as d:
            rep = lg.labgen(rows, pathlib.Path(d) / "labs", generated_at="t", write=False)
        self.assertEqual(rep["counts"]["emitted"], 1)
        self.assertEqual([s["reason"] for s in rep["skipped"]], ["duplicate-slug"])


class IntelSource(unittest.TestCase):
    def test_intel_entry_uses_detected_version_and_technique_seed(self):
        entry = {"component": "drupal", "version": "9.3.0", "cve": "CVE-2022-66666",
                 "technique_seed": {"routed_class": "deserialization", "cwe": "CWE-502",
                                    "owasp": "A08:2021-Integrity Failures"}}
        rec = lg.normalize_intel_entry(entry)
        self.assertEqual(lg.pin_version(rec), "9.3.0")
        self.assertEqual(rec["cwe"], "CWE-502")
        self.assertEqual(rec["vuln_class"], "deserialization")


class ScoreLabsIntegration(unittest.TestCase):
    """benchmark.py --score-labs: planted CVE found = TP (recall); only verified labs count."""
    def labs(self):
        return [
            {"slug": "wp", "cve_id": "CVE-2024-11111", "component": "wordpress", "version": "6.4.2",
             "boot_status": "verified", "expected_class": {"cwe": "CWE-79", "vuln_class": "xss"},
             "expected_evidence": {"match": {"cwe": "CWE-79"}}},
            {"slug": "dr", "cve_id": "CVE-2022-66666", "component": "drupal", "version": "9.3.0",
             "boot_status": "verified", "expected_class": {"cwe": "CWE-502", "vuln_class": "deserialization"},
             "expected_evidence": {"match": {"cwe": "CWE-502"}}},
            {"slug": "lo", "cve_id": "CVE-2023-22222", "component": "lodash", "version": "4.0.0",
             "boot_status": "unverified", "expected_class": {"cwe": "CWE-1321"},
             "expected_evidence": {"match": {"cwe": "CWE-1321"}}},
        ]

    def findings(self):
        return [{"owasp": "A03:2021-Injection", "cwe": "CWE-79", "wstg": "", "title": "Stored XSS"},
                {"owasp": "A05", "cwe": "CWE-16", "wstg": "", "title": "unlabelled extra"}]

    def test_recall_precision_and_exclusion(self):
        r = bm.score_labs(self.labs(), self.findings())
        self.assertEqual(r["labs"]["scored"], 2)              # only the 2 verified labs
        self.assertEqual(r["labs"]["total"], 3)
        self.assertEqual(r["overall"], {"solved": 1, "total": 2, "recall": 0.5})  # wp found, drupal missed
        self.assertEqual(r["labs"]["excluded_unverified"][0]["cve_id"], "CVE-2023-22222")
        per = {x["cve_id"]: x["pass"] for x in r["labs"]["per_lab"]}
        self.assertEqual(per, {"CVE-2024-11111": True, "CVE-2022-66666": False})
        self.assertEqual(r["precision"]["true_positives"], 1)
        self.assertEqual(r["precision"]["fp_candidates"], 1)  # the extra is unlabelled, NOT a confirmed FP

    def test_all_unverified_withholds_numbers(self):
        r = bm.score_labs([self.labs()[2]], self.findings())
        self.assertEqual(r["overall"]["total"], 0)
        self.assertEqual(r["labs"]["scored"], 0)
        self.assertIn("WITHHELD", r["labs"]["note"])

    def test_cli_score_labs_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            dp = pathlib.Path(d)
            labs_dir = dp / "labs"
            for lab in self.labs():
                ld = labs_dir / lab["slug"]
                ld.mkdir(parents=True)
                (ld / "answer_key.json").write_text(json.dumps(lab), encoding="utf-8")
            eng = dp / "eng"
            eng.mkdir()
            (eng / "findings.json").write_text(json.dumps([
                {"id": "RS-1", "title": "Stored XSS", "category": {"owasp": "A03", "cwe": "CWE-79"},
                 "status": "verified", "review": {"verdict": "accepted", "reviewer": "x"}}]), encoding="utf-8")
            out = dp / "res.json"
            r = subprocess.run([sys.executable, str(SCRIPTS / "benchmark.py"), "--score-labs",
                                "--labs-dir", str(labs_dir), "--engagement", str(eng),
                                "--out", str(out), "--json"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            res = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(res["labs"]["scored"], 2)
            self.assertEqual(res["overall"]["solved"], 1)

    def test_cli_baseline_refused_when_zero_verified(self):
        with tempfile.TemporaryDirectory() as d:
            dp = pathlib.Path(d)
            labs_dir = dp / "labs"
            ld = labs_dir / "lo"
            ld.mkdir(parents=True)
            (ld / "answer_key.json").write_text(json.dumps(self.labs()[2]), encoding="utf-8")
            eng = dp / "eng"
            eng.mkdir()
            (eng / "findings.json").write_text(json.dumps([]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(SCRIPTS / "benchmark.py"), "--score-labs",
                                "--labs-dir", str(labs_dir), "--engagement", str(eng), "--baseline"],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("0 VERIFIED", r.stdout + r.stderr)


class Selftests(unittest.TestCase):
    def test_bench_labgen_selftest(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(lg.selftest(), 0)

    def test_benchmark_selftest_still_passes(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bm.selftest(), 0)


if __name__ == "__main__":
    unittest.main()
