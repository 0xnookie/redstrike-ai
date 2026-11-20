#!/usr/bin/env python3
"""
Unit tests for scripts/evidence_seal.py (+ scripts/evidence_capture.py) -- the evidence-capture and
chain-of-custody layer.

Guarantee: evidence is hashed, sealed into evidence/manifest.json, each finding's evidence[].sha256 is
populated, and a later alteration / removal / addition of any artifact is DETECTED by --verify (the
tamper signal the lead's gate hard-fails on). Also checks the independent evidence-capture helper writes
a correctly-named, hash-matching artifact into evidence/<id>/ and that code_citation captures verbatim
source bytes + the pinned shape.

Exercised against TEMP engagement fixtures only (never engagements/). Stdlib only, runnable as
`python test_evidence_seal.py` (the CI convention).
"""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import evidence_seal  # noqa: E402
import evidence_capture  # noqa: E402

HEX64 = __import__("re").compile(r"^[a-f0-9]{64}$")


def _finding(fid, evidence):
    return {"id": fid, "title": "t", "asset": "https://app.acme.com/x", "category": {"cwe": "CWE-79"},
            "severity": "high", "confidence": "confirmed", "status": "verified",
            "evidence": evidence, "reproduction": ["a"],
            "review": {"verdict": "accepted", "reviewer": "x-verify"}}


class _Eng(unittest.TestCase):
    """A synthetic engagement with evidence scattered across the layouts the framework produces."""

    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        eng = pathlib.Path(self._tmp.name)
        # root evidence/<id>/ artifact
        (eng / "evidence" / "RS-2026-001").mkdir(parents=True)
        (eng / "evidence" / "RS-2026-001" / "req.http").write_text("GET / HTTP/1.1\nHost: acme\n", encoding="utf-8")
        # findings/poc artifact
        (eng / "findings" / "poc").mkdir(parents=True)
        (eng / "findings" / "poc" / "exploit.py").write_text("print('poc')\n", encoding="utf-8")
        # per-skill evidence
        (eng / "security-headers" / "evidence").mkdir(parents=True)
        (eng / "security-headers" / "evidence" / "resp.http").write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
        # a source checkout that must be PRUNED (not sealed)
        (eng / "source" / "evidence").mkdir(parents=True)
        (eng / "source" / "evidence" / "not-sealed.txt").write_text("x" * 1000, encoding="utf-8")
        (eng / "runtime").mkdir()
        return eng


class TestHashAndCollect(_Eng):
    def test_sha256_file_matches_hashlib(self):
        eng = self._eng()
        f = eng / "evidence" / "RS-2026-001" / "req.http"
        self.assertEqual(evidence_seal.sha256_file(f), hashlib.sha256(f.read_bytes()).hexdigest())

    def test_collect_finds_evidence_and_poc_prunes_source(self):
        eng = self._eng()
        rels = {evidence_seal._rel(eng, p) for p in evidence_seal.collect_artifacts(eng)}
        self.assertIn("evidence/RS-2026-001/req.http", rels)
        self.assertIn("findings/poc/exploit.py", rels)
        self.assertIn("security-headers/evidence/resp.http", rels)
        # the audited source tree is never sealed
        self.assertNotIn("source/evidence/not-sealed.txt", rels)


class TestSeal(_Eng):
    def test_manifest_shape(self):
        eng = self._eng()
        res = evidence_seal.seal(eng)
        manifest = json.loads((eng / "evidence" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["count"], 3)
        self.assertEqual(len(manifest["artifacts"]), 3)
        for a in manifest["artifacts"]:
            self.assertEqual(set(a), {"path", "sha256", "bytes", "captured_at"})
            self.assertTrue(HEX64.match(a["sha256"]))
            self.assertGreaterEqual(a["bytes"], 0)
        anchor = manifest["time_anchor"]
        self.assertTrue(HEX64.match(anchor["manifest_digest"]))
        self.assertEqual(anchor["artifact_count"], 3)
        self.assertEqual(res["artifact_count"], 3)

    def test_manifest_excludes_itself(self):
        eng = self._eng()
        evidence_seal.seal(eng)
        rels = {evidence_seal._rel(eng, p) for p in evidence_seal.collect_artifacts(eng)}
        self.assertNotIn("evidence/manifest.json", rels)

    def test_populates_finding_sha256_root_and_per_skill_refs(self):
        eng = self._eng()
        # root finding: ref relative to the engagement root
        (eng / "findings.json").write_text(json.dumps([
            _finding("RS-2026-001", [{"type": "request_response", "ref": "evidence/RS-2026-001/req.http"}])
        ]), encoding="utf-8")
        # per-skill finding: ref relative to the skill dir
        (eng / "security-headers" / "findings.json").write_text(json.dumps([
            _finding("RS-2026-010", [{"type": "request_response", "ref": "evidence/resp.http"}])
        ]), encoding="utf-8")

        pop = evidence_seal.seal(eng)["finding_hashes"]
        self.assertEqual(pop["unresolved"], 0)
        self.assertEqual(pop["populated"], 2)

        root = json.loads((eng / "findings.json").read_text(encoding="utf-8"))
        want = evidence_seal.sha256_file(eng / "evidence" / "RS-2026-001" / "req.http")
        self.assertEqual(root[0]["evidence"][0]["sha256"], want)

        sh = json.loads((eng / "security-headers" / "findings.json").read_text(encoding="utf-8"))
        want2 = evidence_seal.sha256_file(eng / "security-headers" / "evidence" / "resp.http")
        self.assertEqual(sh[0]["evidence"][0]["sha256"], want2)

    def test_seal_appends_audit_line(self):
        eng = self._eng()
        evidence_seal.seal(eng)
        lines = (eng / "runtime" / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertTrue(lines)
        rec = json.loads(lines[-1])
        self.assertEqual(set(["ts", "actor", "action", "target", "detail"]) - set(rec), set())
        self.assertEqual(rec["actor"], "evidence-seal")
        self.assertEqual(rec["action"], "seal")
        self.assertTrue(HEX64.match(rec["sha256"]))


class TestVerify(_Eng):
    def test_verify_clean(self):
        eng = self._eng()
        evidence_seal.seal(eng)
        res = evidence_seal.verify_manifest(eng)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["checked"], 3)
        self.assertTrue(res["digest_ok"])
        self.assertEqual(res["mismatches"], [])
        self.assertEqual(res["unsealed"], [])

    def test_verify_detects_alteration(self):
        eng = self._eng()
        evidence_seal.seal(eng)
        # tamper: change an artifact's bytes AFTER sealing
        (eng / "evidence" / "RS-2026-001" / "req.http").write_text("ALTERED\n", encoding="utf-8")
        res = evidence_seal.verify_manifest(eng)
        self.assertFalse(res["ok"])
        self.assertEqual(len(res["mismatches"]), 1)
        self.assertEqual(res["mismatches"][0]["path"], "evidence/RS-2026-001/req.http")

    def test_verify_detects_missing(self):
        eng = self._eng()
        evidence_seal.seal(eng)
        (eng / "findings" / "poc" / "exploit.py").unlink()
        res = evidence_seal.verify_manifest(eng)
        self.assertFalse(res["ok"])
        self.assertIn("findings/poc/exploit.py", res["missing"])

    def test_verify_detects_unsealed_addition(self):
        eng = self._eng()
        evidence_seal.seal(eng)
        (eng / "evidence" / "RS-2026-001" / "added.txt").write_text("new\n", encoding="utf-8")
        res = evidence_seal.verify_manifest(eng)
        self.assertFalse(res["ok"])
        self.assertIn("evidence/RS-2026-001/added.txt", res["unsealed"])

    def test_verify_missing_manifest(self):
        eng = self._eng()
        res = evidence_seal.verify_manifest(eng)
        self.assertFalse(res["ok"])
        self.assertFalse(res["manifest_exists"])


class TestCaptureIntegration(_Eng):
    def test_capture_request_response_roundtrip(self):
        eng = self._eng()
        obj = evidence_capture.capture(eng, "RS-2026-050", "request_response",
                                       content="GET /x HTTP/1.1\n")
        self.assertEqual(obj["type"], "request_response")
        self.assertTrue(HEX64.match(obj["sha256"]))
        art = eng / obj["ref"]
        self.assertTrue(art.is_file())
        self.assertEqual(evidence_seal.sha256_file(art), obj["sha256"])

    def test_capture_code_citation_verbatim_and_shape(self):
        eng = self._eng()
        src = eng / "src" / "sample.py"
        src.parent.mkdir(parents=True)
        src.write_bytes(b"line1\nline2\nline3\nline4\n")   # bytes: verbatim capture must preserve exactly
        obj = evidence_capture.capture(eng, "RS-2026-051", "code_citation",
                                       path=str(src), line="2-3", repo=str(eng), commit="deadbeef")
        self.assertEqual(obj["type"], "code_citation")
        self.assertEqual(set(["type", "file", "line", "commit", "snippet", "ref", "sha256"]) - set(obj), set())
        self.assertEqual(obj["snippet"], "line2\nline3\n")   # verbatim
        self.assertEqual(obj["line"], "2-3")
        self.assertEqual(obj["commit"], "deadbeef")
        self.assertEqual(obj["file"], "src/sample.py")       # relative to repo
        self.assertEqual(evidence_seal.sha256_file(eng / obj["ref"]), obj["sha256"])

    def test_captured_artifact_is_sealed_and_hashes_match(self):
        eng = self._eng()
        obj = evidence_capture.capture(eng, "RS-2026-052", "poc_script", content="print(1)\n",
                                       filename="poc.py")
        (eng / "findings.json").write_text(json.dumps([
            _finding("RS-2026-052", [{"type": "poc_script", "ref": obj["ref"]}])
        ]), encoding="utf-8")
        evidence_seal.seal(eng)
        root = json.loads((eng / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(root[0]["evidence"][0]["sha256"], obj["sha256"])
        res = evidence_seal.verify_manifest(eng)
        self.assertTrue(res["ok"], res)


class TestCli(_Eng):
    def test_cli_seal_then_verify(self):
        eng = self._eng()
        r = subprocess.run([sys.executable, str(SCRIPTS / "evidence_seal.py"),
                            "--engagement", str(eng), "--json"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((eng / "evidence" / "manifest.json").is_file())

        v = subprocess.run([sys.executable, str(SCRIPTS / "evidence_seal.py"),
                            "--engagement", str(eng), "--verify"], capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_cli_verify_exit3_on_tamper(self):
        eng = self._eng()
        subprocess.run([sys.executable, str(SCRIPTS / "evidence_seal.py"),
                        "--engagement", str(eng)], capture_output=True, text=True)
        (eng / "evidence" / "RS-2026-001" / "req.http").write_text("TAMPERED\n", encoding="utf-8")
        v = subprocess.run([sys.executable, str(SCRIPTS / "evidence_seal.py"),
                            "--engagement", str(eng), "--verify"], capture_output=True, text=True)
        self.assertEqual(v.returncode, 3, v.stdout + v.stderr)

    def test_cli_capture(self):
        eng = self._eng()
        r = subprocess.run([sys.executable, str(SCRIPTS / "evidence_capture.py"),
                            "--engagement", str(eng), "--finding", "RS-2026-060",
                            "--type", "dom_capture", "--content", "<html></html>"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        obj = json.loads(r.stdout)
        self.assertEqual(obj["type"], "dom_capture")
        self.assertTrue((eng / obj["ref"]).is_file())


if __name__ == "__main__":
    unittest.main()
