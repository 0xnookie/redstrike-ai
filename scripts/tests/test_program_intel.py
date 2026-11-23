#!/usr/bin/env python3
"""Unit tests for scripts/program_intel.py -- offline bug-bounty program-intel feeder.

Every provider response is MOCKED/injected: these tests make NO live network call. They cover
fetch success, fetch-failure -> placeholder sentinel, the scope.yaml merge preserving the
operator-owned authorized_by, the serializers, and the hacktivity dup-reference.

Stdlib only, runnable as `python test_program_intel.py` (the CI convention) or via pytest.
"""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import program_intel as pi  # noqa: E402


# A fully in-memory fake provider — the seam that lets us drive run()/main() with zero network.
class FakeProvider(pi.Provider):
    def __init__(self, platform="generic", handle="acme", scope=None, policy=None,
                 hacktivity=None, raise_scope=False, raise_policy=False, raise_hacktivity=False):
        super().__init__(platform, handle, http_get=self._forbid_network)
        self._scope = scope
        self._policy = policy
        self._hacktivity = hacktivity or []
        self._raise_scope = raise_scope
        self._raise_policy = raise_policy
        self._raise_hacktivity = raise_hacktivity

    @staticmethod
    def _forbid_network(url):  # pragma: no cover - asserts no test ever hits the wire
        raise AssertionError(f"test attempted a live fetch: {url}")

    def fetch_scope(self):
        if self._raise_scope:
            raise RuntimeError("scope endpoint 503")
        return self._scope

    def fetch_policy(self):
        if self._raise_policy:
            raise RuntimeError("policy endpoint 503")
        return self._policy

    def fetch_hacktivity(self):
        if self._raise_hacktivity:
            raise RuntimeError("hacktivity endpoint 503")
        return self._hacktivity


def _fetched_scope():
    return pi.ProgramScope(
        platform="generic", handle="acme", name="Acme Corp",
        in_scope=[pi.ScopeTarget("*.acme.com", "wildcard"),
                  pi.ScopeTarget("https://api.acme.com", "url"),
                  pi.ScopeTarget("203.0.113.0/24", "cidr")],
        out_of_scope=[pi.ScopeTarget("admin.acme.com", "domain")])


_BASE_SCOPE_YAML = (
    "# header comment\n"
    'engagement: "acme-2026"\n'
    'authorized_by: "ACME security team, written-auth ref #42"\n'
    "window:\n  start: 2026-01-01T00:00:00Z\n  end:   2026-02-01T00:00:00Z\n\n"
    "in_scope:\n  domains:\n    - \"existing.acme.com\"\n  cidrs: []\n  urls: []\n\n"
    "out_of_scope:          # excludes win\n  domains: []\n  cidrs: []\n\n"
    "rules:\n  no_dos: true\n  rate_limit_rps: 20\n\n"
    "notes: >\n  Keep authorization on file.\n")


class BucketClassification(unittest.TestCase):
    def test_wildcard_and_domain_are_domains(self):
        self.assertEqual(pi._bucket_for("*.example.com", ""), "domains")
        self.assertEqual(pi._bucket_for("example.com", ""), "domains")

    def test_url_bucket(self):
        self.assertEqual(pi._bucket_for("https://api.x.com", ""), "urls")
        self.assertEqual(pi._bucket_for("x.com/path", "api"), "urls")

    def test_cidr_bucket(self):
        self.assertEqual(pi._bucket_for("203.0.113.0/24", ""), "cidrs")
        self.assertEqual(pi._bucket_for("10.0.0.1", "ip"), "cidrs")

    def test_asset_type_overrides_sniff(self):
        self.assertEqual(pi._bucket_for("foo", "url"), "urls")

    def test_path_that_is_not_cidr_is_domain(self):
        # a slash that isn't a network must not be miscategorised as a CIDR
        self.assertEqual(pi._bucket_for("example.com/app", ""), "domains")

    def test_scope_target_derives_bucket(self):
        self.assertEqual(pi.ScopeTarget("203.0.113.0/24", "cidr").bucket, "cidrs")
        self.assertEqual(pi.ScopeTarget("*.x.com").bucket, "domains")


class Serializers(unittest.TestCase):
    def test_scope_to_yaml_fetched(self):
        y = pi.scope_to_yaml(_fetched_scope())
        self.assertIn("scope_mode: fetched", y)
        self.assertIn('- "*.acme.com"', y)
        self.assertIn('- "https://api.acme.com"', y)
        self.assertIn('- "203.0.113.0/24"', y)
        self.assertIn('- "admin.acme.com"', y)

    def test_scope_to_yaml_placeholder_is_loud(self):
        y = pi.scope_to_yaml(pi.ProgramScope.placeholder("generic", "acme", "network down"))
        self.assertIn("scope_mode: placeholder", y)
        self.assertIn("network down", y)
        # must NOT present as a clean empty list scope
        self.assertNotIn("domains:", y)

    def test_scope_to_markdown(self):
        md = pi.scope_to_markdown(_fetched_scope())
        self.assertIn("In scope (3)", md)
        self.assertIn("Out of scope (1)", md)
        self.assertIn("api.acme.com", md)

    def test_scope_to_markdown_placeholder(self):
        md = pi.scope_to_markdown(pi.ProgramScope.placeholder("generic", "acme", "boom"))
        self.assertIn("placeholder", md)
        self.assertIn("boom", md)

    def test_hacktivity_markdown(self):
        entries = [pi.HacktivityEntry("Stored XSS in profile", "high", "XSS", "resolved", "2025-01-01",
                                      "https://h1/r/1")]
        md = pi.hacktivity_to_markdown(entries, "generic", "acme")
        self.assertIn("Stored XSS in profile", md)
        self.assertIn("1 disclosed report", md)

    def test_hacktivity_markdown_empty(self):
        md = pi.hacktivity_to_markdown([], "generic", "acme")
        self.assertIn("No disclosed reports", md)

    def test_hacktivity_markdown_escapes_pipes(self):
        md = pi.hacktivity_to_markdown([pi.HacktivityEntry("a | b")], "generic", "acme")
        self.assertIn("a \\| b", md)


class ScopeYamlMerge(unittest.TestCase):
    def test_merge_preserves_authorized_by(self):
        merged = pi.merge_scope_into_yaml_text(_BASE_SCOPE_YAML, _fetched_scope())
        self.assertIn('authorized_by: "ACME security team, written-auth ref #42"', merged)

    def test_merge_unions_in_and_out_scope(self):
        merged = pi.merge_scope_into_yaml_text(_BASE_SCOPE_YAML, _fetched_scope())
        self.assertIn("existing.acme.com", merged)   # original kept
        self.assertIn("*.acme.com", merged)          # added
        self.assertIn("https://api.acme.com", merged)  # url bucket: [] -> block list
        self.assertIn("203.0.113.0/24", merged)      # cidr bucket
        self.assertIn("admin.acme.com", merged)      # out_of_scope added

    def test_merge_preserves_other_keys_and_comments(self):
        merged = pi.merge_scope_into_yaml_text(_BASE_SCOPE_YAML, _fetched_scope())
        self.assertIn("# header comment", merged)
        self.assertIn("# excludes win", merged)
        self.assertIn("rate_limit_rps: 20", merged)
        self.assertIn("Keep authorization on file.", merged)

    def test_merge_is_idempotent(self):
        once = pi.merge_scope_into_yaml_text(_BASE_SCOPE_YAML, _fetched_scope())
        twice = pi.merge_scope_into_yaml_text(once, _fetched_scope())
        self.assertEqual(once, twice)

    def test_merge_dedupes_against_existing(self):
        scope = pi.ProgramScope("generic", "acme",
                                in_scope=[pi.ScopeTarget("existing.acme.com", "domain")])
        merged = pi.merge_scope_into_yaml_text(_BASE_SCOPE_YAML, scope)
        self.assertEqual(merged.count("existing.acme.com"), 1)

    def test_merge_into_real_template(self):
        tmpl = (ROOT / "engagements" / "_template" / "scope.yaml").read_text(encoding="utf-8")
        merged = pi.merge_scope_into_yaml_text(tmpl, _fetched_scope())
        # the template's operator content must survive untouched
        self.assertIn('authorized_by: "<client security contact', merged)
        self.assertIn("approval_required_phases", merged)
        self.assertIn("*.acme.com", merged)

    def test_merge_refuses_placeholder(self):
        ph = pi.ProgramScope.placeholder("generic", "acme", "boom")
        with self.assertRaises(ValueError):
            pi.merge_scope_into_yaml_text(_BASE_SCOPE_YAML, ph)

    def test_merge_creates_block_when_top_key_absent(self):
        txt = 'authorized_by: "x"\nin_scope:\n  domains: []\n  cidrs: []\n  urls: []\n'
        merged = pi.merge_scope_into_yaml_text(txt, _fetched_scope())
        self.assertIn("out_of_scope:", merged)
        self.assertIn("admin.acme.com", merged)


class GenericProvider(unittest.TestCase):
    def _fixtures(self):
        return {
            "SCOPE": json.dumps({
                "name": "Acme",
                "in_scope": [{"identifier": "*.acme.com", "asset_type": "wildcard",
                              "eligible_for_bounty": True},
                             {"identifier": "", "asset_type": "domain"}],  # blank identifier dropped
                "out_of_scope": [{"identifier": "legacy.acme.com", "asset_type": "domain"}]}),
            "POLICY": json.dumps({"offers_bounties": True, "submission_allowed": True,
                                  "disallowed": ["no_dos", "no_automated_scanning"],
                                  "safe_harbor": True, "notes": "Be nice."}),
            "HACK": json.dumps({"entries": [
                {"title": "IDOR on invoices", "severity": "high", "weakness": "IDOR",
                 "state": "resolved", "disclosed_at": "2024-06-01", "url": "https://h/1"}]}),
        }

    def _prov(self, **over):
        fx = self._fixtures()
        kwargs = dict(scope_url="SCOPE", policy_url="POLICY", hacktivity_url="HACK",
                      http_get=lambda u: fx[u])
        kwargs.update(over)
        return pi.GenericJsonProvider("generic", "acme", **kwargs)

    def test_fetch_scope_maps_and_drops_blank(self):
        sc = self._prov().fetch_scope()
        self.assertEqual(sc.name, "Acme")
        self.assertEqual([t.identifier for t in sc.in_scope], ["*.acme.com"])
        self.assertEqual([t.identifier for t in sc.out_of_scope], ["legacy.acme.com"])

    def test_fetch_policy(self):
        pol = self._prov().fetch_policy()
        self.assertTrue(pol.offers_bounties and pol.safe_harbor)
        self.assertEqual(pol.disallowed, ["no_dos", "no_automated_scanning"])

    def test_fetch_hacktivity(self):
        hv = self._prov().fetch_hacktivity()
        self.assertEqual(len(hv), 1)
        self.assertEqual(hv[0].weakness, "IDOR")

    def test_hacktivity_accepts_bare_list(self):
        p = pi.GenericJsonProvider("generic", "acme", hacktivity_url="H",
                                   http_get=lambda u: json.dumps([{"title": "t"}]))
        self.assertEqual(len(p.fetch_hacktivity()), 1)

    def test_missing_urls_return_empty_not_error(self):
        p = pi.GenericJsonProvider("generic", "acme", scope_url="SCOPE",
                                   http_get=lambda u: self._fixtures()[u])
        self.assertIsNone(p.fetch_policy())
        self.assertEqual(p.fetch_hacktivity(), [])

    def test_scope_without_url_raises(self):
        with self.assertRaises(ValueError):
            pi.GenericJsonProvider("generic", "acme").fetch_scope()


class PlatformStubs(unittest.TestCase):
    def test_named_stubs_are_not_implemented(self):
        for plat in ("hackerone", "bugcrowd", "intigriti"):
            prov = pi.get_provider(plat, "acme")
            with self.assertRaises(NotImplementedError):
                prov.fetch_scope()

    def test_unknown_platform_raises(self):
        with self.assertRaises(ValueError):
            pi.get_provider("nope", "acme")

    def test_get_provider_generic(self):
        self.assertIsInstance(pi.get_provider("generic", "acme", scope_url="x"),
                              pi.GenericJsonProvider)


class CollectAndUsable(unittest.TestCase):
    def test_collect_success(self):
        sc, pol, hv = pi.collect_program_intel(
            FakeProvider(scope=_fetched_scope(),
                         policy=pi.ProgramPolicy("generic", "acme", offers_bounties=True),
                         hacktivity=[pi.HacktivityEntry("x")]))
        self.assertFalse(sc.is_placeholder)
        self.assertTrue(pol.offers_bounties)
        self.assertEqual(len(hv), 1)

    def test_collect_scope_exception_is_placeholder(self):
        sc, _, _ = pi.collect_program_intel(FakeProvider(raise_scope=True))
        self.assertTrue(sc.is_placeholder)
        self.assertIn("scope fetch failed", sc.placeholder_reason)

    def test_collect_empty_in_scope_is_placeholder(self):
        empty = pi.ProgramScope("generic", "acme", in_scope=[],
                                out_of_scope=[pi.ScopeTarget("x.com", "domain")])
        sc, _, _ = pi.collect_program_intel(FakeProvider(scope=empty))
        self.assertTrue(sc.is_placeholder)

    def test_collect_policy_and_hacktivity_failures_are_nonfatal(self):
        sc, pol, hv = pi.collect_program_intel(
            FakeProvider(scope=_fetched_scope(), raise_policy=True, raise_hacktivity=True))
        self.assertFalse(sc.is_placeholder)
        self.assertIsNone(pol)
        self.assertEqual(hv, [])

    def test_is_usable_scope(self):
        self.assertTrue(pi.is_usable_scope(_fetched_scope().to_dict()))
        self.assertFalse(pi.is_usable_scope(
            pi.ProgramScope.placeholder("generic", "acme", "boom").to_dict()))
        self.assertFalse(pi.is_usable_scope({}))
        self.assertFalse(pi.is_usable_scope("not a dict"))


class RunOrchestration(unittest.TestCase):
    def test_run_success_writes_three_artifacts_and_merges(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(_BASE_SCOPE_YAML, encoding="utf-8")
            res = pi.run(FakeProvider(scope=_fetched_scope(),
                                      policy=pi.ProgramPolicy("generic", "acme", offers_bounties=True),
                                      hacktivity=[pi.HacktivityEntry("x", "low", "CSRF")]), eng)
            self.assertEqual(res["scope_mode"], pi.SCOPE_MODE_FETCHED)
            self.assertTrue(res["usable"])
            self.assertTrue(res["merged_scope_yaml"])
            # program_scope.json valid + carries scope_mode + policy
            ps = json.loads((eng / "program_scope.json").read_text(encoding="utf-8"))
            self.assertEqual(ps["scope_mode"], "fetched")
            self.assertTrue(ps["policy"]["offers_bounties"])
            self.assertEqual(ps["hacktivity_count"], 1)
            # scope.yaml merged + authorized_by preserved
            sy = (eng / "scope.yaml").read_text(encoding="utf-8")
            self.assertIn("written-auth ref #42", sy)
            self.assertIn("*.acme.com", sy)
            # hacktivity.md written
            self.assertIn("CSRF", (eng / "hacktivity.md").read_text(encoding="utf-8"))

    def test_run_placeholder_does_not_touch_scope_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(_BASE_SCOPE_YAML, encoding="utf-8")
            res = pi.run(FakeProvider(raise_scope=True), eng)
            self.assertEqual(res["scope_mode"], pi.SCOPE_MODE_PLACEHOLDER)
            self.assertFalse(res["usable"])
            self.assertFalse(res["merged_scope_yaml"])
            # scope.yaml must be byte-for-byte untouched (fail-closed)
            self.assertEqual((eng / "scope.yaml").read_text(encoding="utf-8"), _BASE_SCOPE_YAML)
            # program_scope.json is the sentinel
            ps = json.loads((eng / "program_scope.json").read_text(encoding="utf-8"))
            self.assertEqual(ps["scope_mode"], "placeholder")
            self.assertTrue(ps["placeholder_reason"])
            self.assertEqual(ps["in_scope"], [])

    def test_run_no_merge_writes_intel_only(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "scope.yaml").write_text(_BASE_SCOPE_YAML, encoding="utf-8")
            res = pi.run(FakeProvider(scope=_fetched_scope()), eng, do_merge=False)
            self.assertFalse(res["merged_scope_yaml"])
            self.assertEqual((eng / "scope.yaml").read_text(encoding="utf-8"), _BASE_SCOPE_YAML)
            self.assertTrue((eng / "program_scope.json").is_file())

    def test_run_creates_engagement_dir(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "new" / "sub"
            pi.run(FakeProvider(scope=_fetched_scope()), eng)
            self.assertTrue((eng / "program_scope.json").is_file())
            # no pre-existing scope.yaml -> created from the minimal template, authorized_by placeholder
            sy = (eng / "scope.yaml").read_text(encoding="utf-8")
            self.assertIn("FILL IN", sy)
            self.assertIn("*.acme.com", sy)


class MainCLI(unittest.TestCase):
    def _factory(self, provider):
        return lambda *a, **k: provider

    @staticmethod
    def _run_main(argv, **kw):
        # swallow the CLI's stdout/stderr so test logs stay clean
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return pi.main(argv, **kw)

    def test_main_success_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "scope.yaml").write_text(_BASE_SCOPE_YAML, encoding="utf-8")
            rc = self._run_main(["generic", "acme", "--engagement", d],
                                provider_factory=self._factory(FakeProvider(scope=_fetched_scope())))
            self.assertEqual(rc, 0)

    def test_main_placeholder_exit_three(self):
        with tempfile.TemporaryDirectory() as d:
            rc = self._run_main(["generic", "acme", "--engagement", d],
                                provider_factory=self._factory(FakeProvider(raise_scope=True)))
            self.assertEqual(rc, 3)
            # sentinel still written
            self.assertTrue((pathlib.Path(d) / "program_scope.json").is_file())

    def test_main_unknown_platform_exit_two(self):
        with tempfile.TemporaryDirectory() as d:
            rc = self._run_main(["nope", "acme", "--engagement", d])  # ValueError -> exit 2
            self.assertEqual(rc, 2)

    def test_main_selftest(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(pi.main(["--selftest"]), 0)


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        pi.selftest()


if __name__ == "__main__":
    unittest.main()
