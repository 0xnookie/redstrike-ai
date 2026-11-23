import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli.hooks import evidence_ref_gate as g  # noqa: E402


class _Eng:
    """A temp engagement dir with the usual report/findings layout."""

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._td.name) / "eng"
        (self.dir / "runtime").mkdir(parents=True)
        (self.dir / "report").mkdir()
        (self.dir / "exposed-surface" / "evidence").mkdir(parents=True)
        (self.dir / "findings" / "evidence").mkdir(parents=True)
        return self.dir

    def __exit__(self, *a):
        self._td.cleanup()


def _dec(tool, ti, eng):
    return g.evaluate(tool, ti, eng, eng)["decision"]


class TestLocalArtifactRef(unittest.TestCase):
    def test_local_artifact_refs(self):
        self.assertTrue(g.is_local_artifact_ref("poc/x.png"))
        self.assertTrue(g.is_local_artifact_ref("evidence/req.har"))
        self.assertTrue(g.is_local_artifact_ref("exposed-surface/confirmed.jsonl"))

    def test_urls_and_anchors_are_not_local_artifacts(self):
        for ref in ("https://acme.com/x.png", "//cdn/x.png", "#section", "mailto:a@b.c",
                    "data:image/png;base64,AAAA", "tel:+1"):
            self.assertFalse(g.is_local_artifact_ref(ref), ref)

    def test_non_artifact_extension_is_skipped(self):
        # a link to another section/doc without an artifact extension is not checked
        self.assertFalse(g.is_local_artifact_ref("some/path"))
        self.assertFalse(g.is_local_artifact_ref("notes.py"))


class TestCitedRefs(unittest.TestCase):
    def test_json_findings_refs_extracted(self):
        doc = json.dumps([
            {"id": "RS-1", "evidence": [{"type": "screenshot", "ref": "poc/a.png"},
                                        {"type": "code_citation", "file": "src/x.php", "line": 3,
                                         "snippet": "y"}],
             "cleanup": {"ref": "cleanup/c.txt"}}
        ])
        refs = g.cited_refs(doc, is_json=True)
        self.assertIn("poc/a.png", refs)
        self.assertIn("cleanup/c.txt", refs)
        self.assertNotIn("src/x.php", refs)  # code_citation `file` is a source path, not a vault artifact

    def test_markdown_image_and_link_targets(self):
        md = "intro ![shot](evidence/a.png) and [req/resp](evidence/b.har) and [docs](#anchor)"
        refs = g.cited_refs(md, is_json=False)
        self.assertIn("evidence/a.png", refs)
        self.assertIn("evidence/b.har", refs)
        self.assertNotIn("#anchor", refs)

    def test_malformed_json_falls_back_to_regex(self):
        broken = '{"findings": [ {"evidence":[{"ref":"poc/x.png"}  BROKEN'
        refs = g.cited_refs(broken, is_json=True)
        self.assertIn("poc/x.png", refs)


class TestEvaluateScoping(unittest.TestCase):
    def test_dangling_ref_in_consolidated_report_denies(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "report" / "findings_consolidated.json"),
                  "content": json.dumps([{"id": "RS-1", "evidence": [
                      {"type": "screenshot", "ref": "report/evidence/missing.png"}]}])}
            self.assertEqual(_dec("Write", ti, eng), "deny")

    def test_existing_ref_passes(self):
        with _Eng() as eng:
            (eng / "exposed-surface" / "evidence" / "real.txt").write_text("x")
            ti = {"file_path": str(eng / "exposed-surface" / "findings.json"),
                  "content": json.dumps([{"id": "RS-2", "evidence": [
                      {"type": "tool_output", "ref": "exposed-surface/evidence/real.txt"}]}])}
            self.assertEqual(_dec("Write", ti, eng), "pass")

    def test_basename_fallback_resolves(self):
        with _Eng() as eng:
            (eng / "findings" / "evidence" / "shot.png").write_text("x")
            ti = {"file_path": str(eng / "report" / "report.md"),
                  "content": "![p](shot.png)"}  # only a basename cited; resolved under findings/evidence
            self.assertEqual(_dec("Write", ti, eng), "pass")

    def test_dangling_markdown_image_in_report_md_denies(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "report" / "report.md"),
                  "content": "proof: ![poc](evidence/nope.png)"}
            self.assertEqual(_dec("Write", ti, eng), "deny")

    def test_arbitrary_non_report_write_passes(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "notes.md"), "content": "![x](missing.png)"}
            self.assertEqual(_dec("Write", ti, eng), "pass")
            ti2 = {"file_path": str(eng / "exposed-surface" / "scratch.json"),
                   "content": json.dumps([{"evidence": [{"ref": "gone.png"}]}])}
            self.assertEqual(_dec("Write", ti2, eng), "pass")

    def test_runtime_write_is_never_a_report(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "runtime" / "findings.json"),
                  "content": json.dumps([{"evidence": [{"ref": "gone.png"}]}])}
            self.assertEqual(_dec("Write", ti, eng), "pass")

    def test_submissions_draft_is_a_target(self):
        with _Eng() as eng:
            (eng / "submissions").mkdir()
            ti = {"file_path": str(eng / "submissions" / "sub1.md"),
                  "content": "see ![shot](evidence/missing.png)"}
            self.assertEqual(_dec("Write", ti, eng), "deny")

    def test_file_outside_engagement_passes(self):
        with _Eng() as eng:
            other = eng.parent / "elsewhere" / "report.md"
            ti = {"file_path": str(other), "content": "![x](missing.png)"}
            self.assertEqual(_dec("Write", ti, eng), "pass")


class TestEvaluateFailOpen(unittest.TestCase):
    def test_no_eng_dir_passes(self):
        ti = {"file_path": "/x/report/report.md", "content": "![a](missing.png)"}
        self.assertEqual(g.evaluate("Write", ti, None, pathlib.Path("/x"))["decision"], "pass")

    def test_non_write_tool_passes(self):
        with _Eng() as eng:
            self.assertEqual(_dec("Bash", {"command": "curl x"}, eng), "pass")

    def test_edit_new_string_scanned(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "report" / "report.md"),
                  "old_string": "x", "new_string": "added ![p](evidence/ghost.png)"}
            self.assertEqual(_dec("Edit", ti, eng), "deny")

    def test_empty_content_passes(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "report" / "report.md"), "content": "   "}
            self.assertEqual(_dec("Write", ti, eng), "pass")


if __name__ == "__main__":
    unittest.main()
