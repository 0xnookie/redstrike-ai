#!/usr/bin/env python3
"""
Unit tests for scripts/surface.py -- the surface-coverage ledger (recall fix #5).

Guarantee: a surface element recon DISCOVERED but no executor TESTED (and that wasn't skipped with a
reason) is a recall gap — the leak category coverage cannot see (20 injectable params found, 2 tested,
"sqli: attempted, 0 findings" still reads clean). Routed elements start `discovered`; unroutable ones
are `n/a`; `tested`/reasoned-`skipped` clear.

Stdlib only, runnable as `python test_surface.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import surface as sf  # noqa: E402


class Routing(unittest.TestCase):
    def test_param_routes_to_injection_and_more(self):
        r = sf.route_surface("param")
        self.assertIn("sqli", r)
        self.assertIn("xss", r)

    def test_identity_routes_to_authz(self):
        self.assertEqual(sf.route_surface("identity"), ["authz", "api"])

    def test_unknown_kind_routes_nowhere(self):
        self.assertEqual(sf.route_surface("mystery"), [])


class PlanAndValidate(unittest.TestCase):
    def _plan(self):
        return sf.plan_from_items("demo", [
            {"kind": "param", "value": "q", "discovered_by": "content-discovery"},
            {"kind": "param", "value": "q"},            # duplicate -> dropped
            {"kind": "identity", "value": "userA"},
            {"kind": "sink", "value": "x"},
        ])

    def test_plan_dedupes_and_routes(self):
        led = self._plan()
        self.assertEqual(len(led["surfaces"]), 3)
        q = next(s for s in led["surfaces"] if s["value"] == "q")
        self.assertEqual(q["status"], "discovered")
        self.assertTrue(q["routed_to"])

    def test_invalid_kind_is_rejected_not_na(self):
        # an out-of-enum kind (e.g. the inbox `content` surface) is REJECTED at ingest, never
        # folded into the ledger as n/a where a gate would read it as an accounted-for element.
        good, bad = sf.partition_items([{"kind": "content", "value": "/x.xml"},
                                        {"kind": "param", "value": "q"}])
        self.assertEqual([g["value"] for g in good], ["q"])
        self.assertEqual([b["kind"] for b in bad], ["content"])
        self.assertTrue(bad[0]["_reject_reason"])
        led = sf.plan_from_items("demo", [{"kind": "weird", "value": "z"}], warn=False)
        self.assertEqual(led["surfaces"], [])

    def test_valid_kinds_match_schema_enum(self):
        import json
        schema = json.loads((HERE.parents[2] / "skills/_contract/surface_ledger.schema.json").read_text())
        self.assertEqual(set(sf.VALID_KINDS), set(schema["$defs"]["surface"]["properties"]["kind"]["enum"]))

    def test_discovered_routed_surface_is_a_gap(self):
        led = self._plan()
        ok, _l, msgs = sf.validate(led)
        self.assertFalse(ok)
        self.assertTrue(any("untested surface" in m for m in msgs))

    def test_tested_clears(self):
        led = self._plan()
        for s in led["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        self.assertTrue(sf.validate(led)[0])

    def test_skipped_needs_reason(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "q"}])
        led["surfaces"][0]["status"] = "skipped"
        led["surfaces"][0]["reason"] = ""
        self.assertFalse(sf.validate(led)[0])
        led["surfaces"][0]["reason"] = "login param — auth class owns it"
        self.assertTrue(sf.validate(led)[0])

    def test_empty_ledger_lenient_but_strict_fails(self):
        self.assertTrue(sf.validate({"surfaces": []})[0])
        self.assertFalse(sf.validate({"surfaces": []}, strict=True)[0])


class SurfaceGaps(unittest.TestCase):
    def test_gaps_for_recall_audit(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "id"}])
        g = sf.surface_gaps(led)
        self.assertEqual(g[0]["type"], "untested-surface")
        self.assertEqual(g[0]["severity"], "high")

    def test_no_gap_once_tested(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "id"}])
        led["surfaces"][0]["status"] = "tested"
        self.assertEqual(sf.surface_gaps(led), [])


class MergeReplan(unittest.TestCase):
    """Universal emission: `--plan` must be idempotent — re-running preserves tested/skipped progress
    and adds only new elements, so recon can emit the ledger every run (and late feeders / the
    re-convergence loop can re-emit) without clobbering a mark."""

    def _tested_base(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "q"}, {"kind": "param", "value": "id"}])
        q = next(s for s in led["surfaces"] if s["value"] == "q")
        q["status"] = "tested"
        q.setdefault("consumed_by", []).append("sqli")
        return led

    def test_merge_preserves_progress_and_adds_new(self):
        led = self._tested_base()
        merged = sf.merge_plan(led, [
            {"kind": "param", "value": "q"},           # present -> untouched (stays tested)
            {"kind": "param", "value": "id"},          # present -> untouched
            {"kind": "identity", "value": "userB"},    # NEW
        ])
        self.assertEqual(merged["_last_merge_added"], 1)
        bv = {s["value"]: s for s in merged["surfaces"]}
        self.assertEqual(bv["q"]["status"], "tested")
        self.assertIn("sqli", bv["q"]["consumed_by"])
        self.assertEqual(bv["userB"]["status"], "discovered")
        self.assertEqual(len(merged["surfaces"]), 3)

    def test_merge_is_idempotent(self):
        led = self._tested_base()
        once = sf.merge_plan(led, [{"kind": "identity", "value": "userB"}])
        self.assertEqual(once["_last_merge_added"], 1)
        twice = sf.merge_plan(once, [{"kind": "identity", "value": "userB"}])
        self.assertEqual(twice["_last_merge_added"], 0)
        self.assertEqual(len(twice["surfaces"]), 3)


class Attribution(unittest.TestCase):
    """A param carries its endpoint attribution (name@/path) so the SAME name on two endpoints is two
    distinct surface elements — not one 'tested once, looks covered' row (fix #1)."""

    def test_path_and_params_splits_query(self):
        path, names = sf._path_and_params("/_next/image?url=x&w=64")
        self.assertEqual(path, "/_next/image")
        self.assertEqual(names, ["url", "w"])

    def test_path_and_params_strips_scheme_host(self):
        path, names = sf._path_and_params("https://host/a/b?q=1")
        self.assertEqual(path, "/a/b")
        self.assertEqual(names, ["q"])

    def test_attr_param_distinguishes_endpoints(self):
        self.assertEqual(sf._attr_param("url", "/_next/image"), "url@/_next/image")
        a = sf.plan_from_items("demo", [{"kind": "param", "value": "url@/_next/image"},
                                        {"kind": "param", "value": "url@/avatar"}])
        self.assertEqual(len({s["id"] for s in a["surfaces"]}), 2)


class ContentReroute(unittest.TestCase):
    """fix #5: a content-kind discovery (sitemap/robots/API schema) routes BACK to content-discovery for
    URL/objref extraction — it is never a testable surface-ledger element and never silently dropped."""

    def test_content_is_not_a_ledger_kind(self):
        self.assertNotIn("content", sf.VALID_KINDS)
        self.assertEqual(sf.followup_route("content"), "content-discovery")
        self.assertIsNone(sf.followup_route("param"))

    def test_content_reroutes_directives(self):
        rr = sf.content_reroutes([{"kind": "content", "value": "/sitemap.xml", "discovered_by": "hunt"},
                                  {"kind": "param", "value": "q"}])
        self.assertEqual(len(rr), 1)
        self.assertEqual(rr[0]["route_to"], "content-discovery")
        self.assertEqual(rr[0]["value"], "/sitemap.xml")
        self.assertIn("extract", rr[0]["action"])


class LoadReconSurfaces(unittest.TestCase):
    """fix #1: the ledger ingestion must read the REAL feeder layouts — js-analysis'
    out/<site>/findings/*.jsonl tree, content-discovery's endpoints.txt + params*.txt + content.json,
    and the previously-unpopulated kinds (sink/header/form/upload/auth-flow)."""

    def _build(self, eng: pathlib.Path):
        # js-analysis: the REAL out/<site>/findings tree (NOT a flat js-analysis/*.jsonl)
        jf = eng / "js-analysis" / "out" / "app.target.com" / "findings"
        jf.mkdir(parents=True)
        (jf / "endpoints.jsonl").write_text(
            json.dumps({"url": "/_next/image?url=1&w=64", "state": "live"}) + "\n"
            + json.dumps({"url": "https://app.target.com/api/me"}) + "\n", encoding="utf-8")
        (jf / "params.jsonl").write_text(
            json.dumps({"name": "q", "kind": "query", "endpoint": "/search"}) + "\n"
            + json.dumps({"name": "X-Debug", "kind": "header"}) + "\n", encoding="utf-8")
        (jf / "gadgets.jsonl").write_text(
            json.dumps({"sink": "innerHTML", "source_file": "main.js", "line": 42}) + "\n", encoding="utf-8")
        # content-discovery: endpoints.txt (previously ignored) + params.txt + content.json
        cd = eng / "content-discovery"
        cd.mkdir(parents=True)
        (cd / "endpoints.txt").write_text("/admin\n# comment\n/login\n", encoding="utf-8")
        (cd / "params.txt").write_text("token\n", encoding="utf-8")
        (cd / "content.json").write_text(json.dumps({
            "routes": [{"path": "/signup", "type": "form", "params": ["email", "pw"]},
                       {"path": "/item?id=7", "type": "html"}],
            "notable_sinks": {"ssti": ["render(name)"]}}), encoding="utf-8")
        # host-discovery, authz-context, auth-context, file-context
        (eng / "host-discovery").mkdir()
        (eng / "host-discovery" / "host_discovery.json").write_text(json.dumps({
            "live_hosts": [{"url": "https://app.target.com"}],
            "api_endpoints": [{"path": "/api/v1/users"}]}), encoding="utf-8")
        (eng / "authz-context").mkdir()
        (eng / "authz-context" / "authz_context.json").write_text(json.dumps({
            "identities": [{"label": "userA"}, {"label": "userB"}]}), encoding="utf-8")
        (eng / "auth-context").mkdir()
        (eng / "auth-context" / "auth_context.json").write_text(json.dumps({
            "flows": [{"id": "f1", "kind": "login"}, {"id": "f2", "kind": "registration"}]}), encoding="utf-8")
        (eng / "file-context").mkdir()
        (eng / "file-context" / "file_context.json").write_text(json.dumps({
            "targets": [{"id": "u1", "endpoint": "/upload", "kind": "upload"},
                        {"id": "r1", "endpoint": "/download", "kind": "download"}]}), encoding="utf-8")

    def test_reads_all_real_layouts(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._build(eng)
            items = sf.load_recon_surfaces(eng)
            by_kind = {}
            for it in items:
                by_kind.setdefault(it["kind"], set()).add(it["value"])

            # js-analysis endpoints from the REAL out/*/findings path (the old flat path never existed)
            self.assertIn("/_next/image", by_kind["endpoint"])
            self.assertIn("/api/me", by_kind["endpoint"])
            # param -> endpoint attribution from a query string on the endpoint
            self.assertIn("url@/_next/image", by_kind["param"])
            # params.jsonl: a query param attributed to its endpoint; a header-carrier -> header kind
            self.assertIn("q@/search", by_kind["param"])
            self.assertIn("X-Debug", by_kind.get("header", set()))
            # gadgets.jsonl -> sink kind (was declared but never populated)
            self.assertTrue(any("innerHTML" in s for s in by_kind.get("sink", set())))
            # content-discovery endpoints.txt (previously ignored entirely)
            self.assertIn("/admin", by_kind["endpoint"])
            self.assertIn("/login", by_kind["endpoint"])
            self.assertIn("token", by_kind["param"])
            # content.json: a form route -> form kind; its fields -> attributed params; notable sink
            self.assertIn("/signup", by_kind.get("form", set()))
            self.assertIn("email@/signup", by_kind["param"])
            self.assertTrue(any("render(name)" in s for s in by_kind.get("sink", set())))
            # host-discovery, identities, auth-flows, uploads
            self.assertIn("/api/v1/users", by_kind.get("api-operation", set()))
            self.assertEqual(by_kind.get("identity"), {"userA", "userB"})
            self.assertIn("registration:f2", by_kind.get("auth-flow", set()))
            self.assertIn("/upload", by_kind.get("upload", set()))
            self.assertNotIn("/download", by_kind.get("upload", set()))

    def test_plan_from_loaded_surfaces_is_clean(self):
        # every loaded item has a valid kind, so none is rejected into the void; the ledger routes them.
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            self._build(eng)
            items = sf.load_recon_surfaces(eng)
            good, bad = sf.partition_items(items)
            self.assertEqual(bad, [])
            led = sf.plan_from_items("demo", items)
            kinds = {s["kind"] for s in led["surfaces"]}
            # all five formerly-unpopulated kinds now appear in a real plan
            self.assertTrue({"sink", "header", "form", "upload", "auth-flow"}.issubset(kinds), kinds)


class SchemaConformance(unittest.TestCase):
    def test_planned_ledger_matches_schema_keys(self):
        import json
        schema = json.loads((HERE.parents[2] / "skills/_contract/surface_ledger.schema.json").read_text())
        allowed = set(schema["$defs"]["surface"]["properties"])
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "q"}])
        for s in led["surfaces"]:
            self.assertTrue(set(s).issubset(allowed), set(s) - allowed)
        self.assertTrue(set(schema["$defs"]["surface"]["required"]).issubset(set(led["surfaces"][0])))


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        sf.selftest()


if __name__ == "__main__":
    unittest.main()
