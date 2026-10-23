#!/usr/bin/env python3
"""
E3 — first unit tests for scripts/console.py (previously zero coverage).

Covers the pure, offline data-model functions the console server is built on:
engagement discovery, the shallowest-file resolver, verdict/reportable logic,
the multi-layout findings discovery (mirror of verify_completion's — the C2
fix), the server-side severity/chain summary, and scope.yaml parsing — including
the dependency-free `cidrs: []` path that this change fixes.

Nothing here touches the network, npm, a browser, or the built console/out/ —
only the parsing/aggregation helpers. Stdlib only, runnable as
`python test_console.py` (the CI convention — see cli/tests/).
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]                  # scripts/
sys.path.insert(0, str(SCRIPTS))

import console as c  # noqa: E402


def mk(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


def finding(fid="RS-2026-001", severity="high", status="verified", review=None, composite=False):
    f = {"id": fid, "title": "t", "asset": "https://app.acme.com", "severity": severity,
         "confidence": "confirmed", "status": status, "evidence": [], "reproduction": ["x"]}
    if review is not None:
        f["review"] = review
    if composite:
        f["composite"] = True
    return f


SCOPE_YAML = """engagement: "acme-2026"
authorized_by: sec@acme / auth-1
window:
  start: 2026-01-01T00:00:00Z
  end:   2026-01-08T23:59:59Z
in_scope:
  domains:
    - "*.acme.com"
    - "api.acme.com"
  cidrs: []
  urls:
    - "https://app.acme.com"
out_of_scope:
  domains:
    - "admin.acme.com"
  cidrs: []
rules:
  no_dos: true
  rate_limit_rps: 10
notes: >
  single endpoint only
"""


# --------------------------------------------------------------------------- #
class TestDiscovery(unittest.TestCase):
    def test_looks_like_engagement_signals(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.assertFalse(c.looks_like_engagement(root / "missing"))
            empty = root / "empty"; empty.mkdir()
            self.assertFalse(c.looks_like_engagement(empty))
            s = root / "by-scope"; s.mkdir(); (s / "scope.yaml").write_text("x", encoding="utf-8")
            self.assertTrue(c.looks_like_engagement(s))
            r = root / "by-report"; (r / "report").mkdir(parents=True)
            self.assertTrue(c.looks_like_engagement(r))
            h = root / "by-hostdisc"; (h / "host-discovery").mkdir(parents=True)
            self.assertTrue(c.looks_like_engagement(h))

    def test_discover_single_vs_parent_and_skips(self):
        with tempfile.TemporaryDirectory() as d:
            parent = pathlib.Path(d)
            for name in ("acme-2026-01-01", "beta-2026-02-02"):
                (parent / name).mkdir()
                (parent / name / "scope.yaml").write_text("x", encoding="utf-8")
            # a scaffold/template dir must be ignored (starts with "_")
            (parent / "_template").mkdir()
            (parent / "_template" / "scope.yaml").write_text("x", encoding="utf-8")
            (parent / ".hidden").mkdir()
            (parent / ".hidden" / "scope.yaml").write_text("x", encoding="utf-8")

            # parent → every real engagement, template/hidden skipped
            got = {p.name for p in c.discover(parent)}
            self.assertEqual(got, {"acme-2026-01-01", "beta-2026-02-02"})
            # a single engagement dir → just itself
            self.assertEqual(c.discover(parent / "acme-2026-01-01"), [parent / "acme-2026-01-01"])


class TestFilesFor(unittest.TestCase):
    def test_canonical_mapping_and_aliases(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text("x", encoding="utf-8")
            mk(eng / "host-discovery" / "host_discovery.json", {"hosts": []})
            mk(eng / "coverage_ledger.json", {"categories": []})
            mk(eng / "cve-intelligence" / "cve_intel.json", {"entries": []})
            mk(eng / "attack-chain-discovery" / "chains.json", {"chains": []})  # alias
            files = c.files_for(eng)
            self.assertTrue(files["host_discovery.json"].name == "host_discovery.json")
            self.assertIn("coverage_ledger.json", files)
            self.assertIn("cve_intel.json", files)
            # chains.json resolves to the canonical attack_chains.json slot
            self.assertEqual(files["attack_chains.json"].name, "chains.json")
            # scope.json is resolved separately, never via files_for
            self.assertNotIn("scope.json", files)

    def test_shallowest_wins(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "deep" / "deeper" / "coverage_ledger.json", {"a": 1})
            mk(eng / "coverage_ledger.json", {"b": 2})           # shallower
            hit = c._shallowest(eng, "coverage_ledger.json")
            self.assertEqual(hit.parent, eng)


class TestVerdictReportable(unittest.TestCase):
    def test_verdict_precedence(self):
        self.assertEqual(c._verdict(finding(review={"verdict": "blocked"})), "blocked")
        self.assertEqual(c._verdict(finding(status="verified")), "accepted")   # derived
        self.assertEqual(c._verdict(finding(status="rejected")), "rejected")
        self.assertEqual(c._verdict(finding(status="open")), "")

    def test_reportable(self):
        self.assertTrue(c._reportable(finding(status="verified")))
        self.assertTrue(c._reportable(finding(review={"verdict": "blocked"})))
        self.assertFalse(c._reportable(finding(status="rejected")))
        self.assertFalse(c._reportable(finding(status="open")))
        # composite kill-chain finding is excluded from counts (non-additive)
        self.assertFalse(c._reportable(finding(status="verified", composite=True)))
        self.assertFalse(c._reportable({**finding(status="verified"), "_composite": True}))


class TestFindingsDiscovery(unittest.TestCase):
    def test_findings_list_shapes(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            mk(d / "arr.json", [finding()])
            self.assertEqual(len(c._findings_list(d / "arr.json")), 1)
            mk(d / "obj.json", {"findings": [finding(), finding("RS-2026-002")]})
            self.assertEqual(len(c._findings_list(d / "obj.json")), 2)
            mk(d / "num.json", "42")
            self.assertIsNone(c._findings_list(d / "num.json"))
            self.assertIsNone(c._findings_list(d / "missing.json"))

    def test_engagement_findings_layers(self):
        # 1) consolidated report wins and flags is_consolidated
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "report" / "findings_consolidated.json", {"findings": [finding()]})
            lst, is_cons = c.engagement_findings(eng, c.files_for(eng))
            self.assertEqual(len(lst), 1)
            self.assertTrue(is_cons)
        # 2) no consolidated → root findings.json
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "findings.json", [finding(), finding("RS-2026-002")])
            lst, is_cons = c.engagement_findings(eng, c.files_for(eng))
            self.assertEqual(len(lst), 2)
            self.assertFalse(is_cons)
        # 3) neither → UNION of per-skill findings.json (live, pre-reporting: the C2 behavior)
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "xss-reflected" / "findings.json", [finding("RS-2026-001")])
            mk(eng / "sqli-inband" / "findings.json", [finding("RS-2026-002")])
            lst, is_cons = c.engagement_findings(eng, c.files_for(eng))
            self.assertEqual({f["id"] for f in lst}, {"RS-2026-001", "RS-2026-002"})
            self.assertFalse(is_cons)


class TestSummarize(unittest.TestCase):
    def test_reportable_counts_and_chains(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "findings.json", [
                finding("RS-2026-001", severity="high", status="verified"),      # counted
                finding("RS-2026-002", severity="low", status="verified"),        # counted
                finding("RS-2026-003", severity="critical", status="rejected"),   # not counted
                finding("RS-2026-004", severity="high", status="verified", composite=True),  # excluded
            ])
            mk(eng / "attack-chain-discovery" / "chains.json", {"chains": [{"id": 1}, {"id": 2}]})
            s = c.summarize(eng, c.files_for(eng))
            self.assertEqual(s["findings"], 2)
            self.assertEqual(s["high"], 1)
            self.assertEqual(s["low"], 1)
            self.assertEqual(s["critical"], 0)
            self.assertEqual(s["chains"], 2)

    def test_chains_from_consolidated(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "report" / "findings_consolidated.json",
               {"findings": [], "attack_chains": [{"id": "c1"}]})
            s = c.summarize(eng, c.files_for(eng))
            self.assertEqual(s["chains"], 1)


class TestScopeParsing(unittest.TestCase):
    def test_minimal_scope_read_inline_empty_list(self):
        """The fix: `cidrs: []` is an empty list, not the two characters '[' and ']'."""
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "scope.yaml"
            p.write_text(SCOPE_YAML, encoding="utf-8")
            doc = c._minimal_scope_read(p)
            self.assertEqual(doc["in_scope"]["cidrs"], [])
            self.assertEqual(doc["out_of_scope"]["cidrs"], [])
            self.assertEqual(doc["in_scope"]["domains"], ["*.acme.com", "api.acme.com"])

    def test_minimal_scope_read_inline_empty_map(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "scope.yaml"
            p.write_text("top:\n  meta: {}\n  items: []\n", encoding="utf-8")
            doc = c._minimal_scope_read(p)
            self.assertEqual(doc["top"]["meta"], {})
            self.assertEqual(doc["top"]["items"], [])

    def test_scope_yaml_to_json_shape(self):
        """Holds under BOTH PyYAML and the dependency-free reader (post-fix they agree)."""
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "scope.yaml"
            p.write_text(SCOPE_YAML, encoding="utf-8")
            out = c.scope_yaml_to_json(p)
            self.assertEqual(out["engagement"], "acme-2026")
            self.assertEqual(out["target"], "acme.com")              # first domain, '*.' stripped
            self.assertEqual(out["in_scope"]["cidrs"], [])           # <-- the bug, now fixed
            self.assertEqual(out["in_scope"]["domains"], ["*.acme.com", "api.acme.com"])
            self.assertEqual(out["in_scope"]["urls"], ["https://app.acme.com"])
            self.assertEqual(out["out_of_scope"]["domains"], ["admin.acme.com"])
            self.assertEqual(out["window"]["start"], "2026-01-01T00:00:00Z")
            self.assertEqual(out["source"], "scope.yaml")

    def test_scope_for_prefers_scope_json(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "runtime" / "scope.json", {"engagement": "x", "target": "t", "source": "scope.json"})
            got = c.scope_for(eng)
            self.assertEqual(got["source"], "scope.json")


if __name__ == "__main__":
    unittest.main()
