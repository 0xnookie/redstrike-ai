"""Tests for FIX #1 (auth.env materializer) and FIX #7 (toolchain preflight → tooling_health).

Covers:
  • accounts.materialize: creds.json → runtime/auth.env (format, aliases, escaping, idempotency,
    empty/absent no-op, lands under runtime/).
  • preflight.tooling_snapshot / write_tooling (injected probe seam — no real WSL/bash needed).
  • diagnostics.tooling_rollup + the new tooling-degraded classify_outcome branch.
  • a diagnostics run record validates against diagnostics.schema.json BOTH with and without the
    optional tooling_health block (using the repo's bundled stdlib schema-subset validator).
"""
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
CLI = HERE.parents[1]
REPO = HERE.parents[2]
sys.path.insert(0, str(CLI))  # cli/

from redstrike_cli import accounts  # noqa: E402
from redstrike_cli import diagnostics as dg  # noqa: E402
from redstrike_cli import preflight  # noqa: E402

SCHEMA_PATH = REPO / "skills" / "_contract" / "diagnostics.schema.json"


def _load_schema_validator():
    """Load the repo's dependency-free JSON-Schema-subset validator from verify_completion.py."""
    spec = importlib.util.spec_from_file_location(
        "rs_verify_completion", REPO / "skills" / "_contract" / "verify_completion.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._stdlib_schema_errors


def _schema_errors(doc):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return _load_schema_validator()(doc, schema)


def _doc(*records):
    return {"version": dg.DIAG_SCHEMA_VERSION, "engagement": "e",
            "generated_at": "2026-01-01T00:00:00Z", "runs": list(records)}


# ---------------------------------------------------------------- FIX #1 — materialize
class TestMaterialize(unittest.TestCase):
    def _eng_with_accounts(self, tmp):
        eng = pathlib.Path(tmp) / "acme-eng"
        (eng / "runtime").mkdir(parents=True)
        a = accounts.build_account(id="userA", role="user", identity="alice@t.com",
                                   password="pw-alice-123456", cookie="sid=AAA",
                                   headers={"X-Debug": "1"})
        b = accounts.build_account(id="userB", role="admin", token='tok$ecret"B',
                                   headers={"X-Api": "k"})
        accounts.save_creds(eng, {"engagement": eng.name, "accounts": [a, b]})
        return eng

    def test_materialize_writes_runtime_auth_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = self._eng_with_accounts(tmp)
            p = accounts.materialize(eng)
            self.assertIsNotNone(p)
            # lands under runtime/ (gitignored, never served)
            self.assertEqual(p, eng / "runtime" / "auth.env")
            self.assertEqual(p.parent.name, "runtime")
            txt = p.read_text(encoding="utf-8")
            # per-identity, namespaced by (sanitized, uppercased) id
            self.assertIn('USERA_ID="userA"', txt)
            self.assertIn('USERA_ROLE="user"', txt)
            self.assertIn('USERA_PASSWORD="pw-alice-123456"', txt)
            self.assertIn('USERA_COOKIE="sid=AAA"', txt)
            self.assertIn('USERB_ID="userB"', txt)
            self.assertIn("USERB_BEARER=", txt)
            # token header materialized into the namespaced HEADERS block
            self.assertIn("Authorization: Bearer", txt)
            self.assertIn("X-Api: k", txt)
            # flat aliases for the PRIMARY identity (the COOKIE=/HEADERS= tokens js-analysis documents)
            self.assertIn('\nCOOKIE="sid=AAA"', txt)
            self.assertRegex(txt, r"(?m)^HEADERS=")

    def test_shell_metacharacters_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = self._eng_with_accounts(tmp)
            txt = accounts.materialize(eng).read_text(encoding="utf-8")
            # userB bearer carried a `$` and a `"` — both must be backslash-escaped so `source` is safe
            self.assertIn(r"\$ecret", txt)
            self.assertIn(r"\"B", txt)
            self.assertNotIn('tok$ecret"B', txt)  # never the raw, source-breaking form

    def test_idempotent_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = self._eng_with_accounts(tmp)
            first = accounts.materialize(eng).read_bytes()
            second = accounts.materialize(eng).read_bytes()
            self.assertEqual(first, second)  # no volatile timestamp → strictly idempotent

    def test_noop_when_absent_or_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            (eng / "runtime").mkdir(parents=True)
            # absent creds.json
            self.assertIsNone(accounts.materialize(eng))
            self.assertFalse((eng / "runtime" / "auth.env").exists())
            # present but zero accounts
            accounts.save_creds(eng, {"engagement": "eng", "accounts": []})
            self.assertIsNone(accounts.materialize(eng))
            self.assertFalse((eng / "runtime" / "auth.env").exists())

    def test_namespace_dedup_and_sanitize(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            (eng / "runtime").mkdir(parents=True)
            a = accounts.build_account(id="user-x", password="p1aaaaaa")
            b = accounts.build_account(id="user.x", password="p2aaaaaa")  # sanitizes to same base
            accounts.save_creds(eng, {"engagement": "eng", "accounts": [a, b]})
            txt = accounts.materialize(eng).read_text(encoding="utf-8")
            self.assertIn('USER_X_ID="user-x"', txt)
            self.assertIn('USER_X_2_ID="user.x"', txt)  # de-duplicated


# ---------------------------------------------------------------- FIX #7 — tooling_snapshot
class TestToolingSnapshot(unittest.TestCase):
    def test_degraded_when_primaries_absent(self):
        # only fallbacks present → every capability degraded, with the available fallback named
        snap = preflight.tooling_snapshot(
            REPO, shell=lambda tools: {"nmap", "dig", "gobuster", "curl"})
        self.assertEqual(len(snap["capabilities"]), 5)
        by = {c["capability"]: c for c in snap["capabilities"]}
        self.assertFalse(by["http-probe"]["present"])
        self.assertEqual(by["http-probe"]["fallback"], "curl")
        self.assertEqual(by["http-probe"]["status"], "degraded")
        self.assertEqual(by["port-scan"]["fallback"], "nmap")
        # subdomain-enum has NO fallback present → fallback None, still degraded
        self.assertIsNone(by["subdomain-enum"]["fallback"])
        self.assertEqual(by["subdomain-enum"]["status"], "degraded")
        self.assertEqual(snap["overall"], {"degraded_count": 5, "status": "degraded"})

    def test_ok_when_primaries_present(self):
        primaries = {"subfinder", "dnsx", "httpx", "naabu", "ffuf"}
        snap = preflight.tooling_snapshot(REPO, shell=lambda tools: primaries)
        for c in snap["capabilities"]:
            self.assertTrue(c["present"])
            self.assertIsNone(c["fallback"])
            self.assertEqual(c["status"], "ok")
        self.assertEqual(snap["overall"], {"degraded_count": 0, "status": "ok"})

    def test_empty_probe_all_degraded(self):
        snap = preflight.tooling_snapshot(REPO, shell=lambda tools: set())
        self.assertEqual(snap["overall"]["degraded_count"], 5)

    def test_write_tooling_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            snap = preflight.tooling_snapshot(REPO, shell=lambda tools: {"nmap"})
            path = preflight.write_tooling(eng, snap)
            self.assertEqual(path, eng / "runtime" / "tooling.json")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), snap)


# ---------------------------------------------------------------- FIX #7 — tooling_rollup
class TestToolingRollup(unittest.TestCase):
    def _snap(self):
        return preflight.tooling_snapshot(REPO, shell=lambda tools: {"nmap", "curl"})

    def test_rollup_shape(self):
        th = dg.tooling_rollup(self._snap())
        self.assertEqual(set(th), {"capabilities", "overall", "probed_at"})
        self.assertEqual(th["overall"]["status"], "degraded")
        self.assertEqual(th["overall"]["degraded_count"], 5)
        for c in th["capabilities"]:
            self.assertEqual(set(c), {"capability", "primary", "present", "fallback", "status"})

    def test_rollup_none_cases(self):
        self.assertIsNone(dg.tooling_rollup(None))
        self.assertIsNone(dg.tooling_rollup({}))
        self.assertIsNone(dg.tooling_rollup({"capabilities": []}))


# ---------------------------------------------------------------- FIX #7 — classify branch
class TestClassifyToolingBranch(unittest.TestCase):
    def _healthy_transport(self):
        return {"hosts": [], "overall": {"block_rate": 0.0, "worst_host": None, "status": "healthy"}}

    def _degraded_tooling(self):
        return dg.tooling_rollup(preflight.tooling_snapshot(
            REPO, shell=lambda tools: {"nmap", "dig", "curl", "gobuster"}))

    def _empty_recon(self):
        return {"flag": True, "surface_discovered": 0, "signals": 0, "hosts_live": 0}

    def test_tooling_degraded_plus_empty_recon_is_degraded(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0}, None, {"surfaces": []},
            self._healthy_transport(),
            tooling_health=self._degraded_tooling(), empty_recon=self._empty_recon())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("tooling gap", reason)
        self.assertIn("subdomain-enum", reason)  # first degraded capability named

    def test_findings_present_still_produced_despite_degraded_tooling(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 3, "engine_rc": 0}, None, {"surfaces": []},
            self._healthy_transport(),
            tooling_health=self._degraded_tooling(), empty_recon=self._empty_recon())
        self.assertEqual(out, dg.PRODUCED)
        self.assertIsNone(reason)

    def test_non_empty_recon_does_not_trip_tooling_branch(self):
        # degraded tooling but recon found hosts + tested surface → genuinely clean, not tooling-degraded
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0},
            {"categories": [{"status": "attempted"}]},
            {"surfaces": [{"status": "tested"}]},
            self._healthy_transport(),
            tooling_health=self._degraded_tooling(),
            empty_recon={"flag": False, "surface_discovered": 5, "signals": 2, "hosts_live": 3})
        self.assertEqual(out, dg.CLEAN)
        self.assertIsNone(reason)

    def test_ok_tooling_falls_through_to_generic_reason(self):
        ok_tooling = dg.tooling_rollup(preflight.tooling_snapshot(
            REPO, shell=lambda tools: {"subfinder", "dnsx", "httpx", "naabu", "ffuf"}))
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0}, None, {"surfaces": []},
            self._healthy_transport(),
            tooling_health=ok_tooling, empty_recon=self._empty_recon())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("no attack surface", reason)   # generic, NOT the tooling-gap reason
        self.assertNotIn("tooling gap", reason)


# ---------------------------------------------------------------- schema validation
class TestSchemaValidation(unittest.TestCase):
    def test_record_without_tooling_health_validates(self):
        rec = dg.Diagnostics(session="s", mode="interactive", outcome=dg.CLEAN).to_record()
        self.assertNotIn("tooling_health", rec)  # omitted when absent (backward-compatible)
        self.assertEqual(_schema_errors(_doc(rec)), [])

    def test_record_with_tooling_health_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            (eng / "runtime").mkdir(parents=True)
            snap = preflight.tooling_snapshot(REPO, shell=lambda tools: {"nmap", "curl"})
            preflight.write_tooling(eng, snap)
            rec = dg.assemble(eng, session="s", mode="autonomous", started="t0", ended="t1",
                              engine_rc=0, gate_rc=0, summary=None).to_record()
            self.assertIn("tooling_health", rec)
            self.assertEqual(rec["tooling_health"]["overall"]["status"], "degraded")
            self.assertEqual(_schema_errors(_doc(rec)), [])

    def test_schema_version_bumped(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIn("tooling_health", schema["$defs"])
        self.assertIn("tool_capability", schema["$defs"])
        # tooling_health is declared on the run but is NOT required (optional)
        self.assertIn("tooling_health", schema["$defs"]["run"]["properties"])
        self.assertNotIn("tooling_health", schema["$defs"]["run"]["required"])


if __name__ == "__main__":
    unittest.main()
