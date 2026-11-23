import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import engagement, launch, roe, settings  # noqa: E402


class TestAutonomousPrompt(unittest.TestCase):
    """The autonomous prompt must drive the FULL orchestrator pipeline, not just recon."""

    def test_prompt_drives_full_pipeline(self):
        p = launch.autonomous_prompt("acme-2026-11-16")
        self.assertIn("acme-2026-11-16", p)
        self.assertIn("orchestrator", p)
        # it hunts the vuln categories, not just recon
        self.assertIn("xss", p)
        self.assertIn("sqli", p)
        # it must NOT stop after recon
        self.assertIn("Do NOT stop after recon", p)
        # §0 already satisfied + the gated-phase defer-and-continue + hard stop framing
        self.assertIn("SATISFIED", p)
        self.assertIn("HARD STOP", p)
        self.assertIn("report", p)

    def test_prompt_no_longer_says_stop_and_summarize(self):
        p = launch.autonomous_prompt("eid")
        self.assertNotIn("STOP and summarize", p)


class TestAutonomousRoeFullPipeline(unittest.TestCase):
    PROJ = {
        "authorized_by": "sec@acme",
        "window": {"start": "2026-11-01T00:00:00Z", "end": "2026-11-30T23:59:59Z"},
        "in_scope": {"domains": ["*.acme.com"], "cidrs": [], "urls": []},
        "out_of_scope": {"domains": ["admin.acme.com"], "cidrs": []},
        "rules": {"no_dos": True, "rate_limit_rps": 20,
                  "approval_required_phases": ["exploitation", "post-exploitation"]},
    }

    def test_autonomous_roe_full_pipeline_and_defer_continue(self):
        t = roe.render_roe(self.PROJ, "acme-2026-11-16", autonomous=True)
        self.assertIn("AUTONOMOUS", t)
        # full pipeline: do not stop after recon, hunt EVERY class, build the notebook
        self.assertIn("do NOT stop after recon", t)
        self.assertIn("EVERY routed vulnerability class", t)
        self.assertIn("notebook", t)
        # defer-and-continue framing (keeps the phrase older tests assert on)
        self.assertIn("deferred for operator approval", t)
        self.assertIn("CONTINUE", t)
        self.assertIn("HARD STOP", t)
        # {phases} still substitutes the real approval-gated phases
        self.assertIn("exploitation, post-exploitation", t)
        self.assertNotIn("{phases}", t)

    def test_autonomous_roe_does_not_tell_run_to_stop_after_recon(self):
        t = roe.render_roe(self.PROJ, "eid", autonomous=True)
        # the old "Do recon and non-destructive analysis ... STOP" framing must be gone
        self.assertNotIn("STOP at", t)
        self.assertNotIn("the run pauses", t)

    def test_interactive_roe_has_no_autonomous_note(self):
        t = roe.render_roe(self.PROJ, "eid", autonomous=False)
        self.assertNotIn("AUTONOMOUS run", t)
        self.assertNotIn("deferred for operator approval", t)


class TestEngagementDisciplinePreamble(unittest.TestCase):
    """The always-on anti-pattern reminder is folded into the appended prompt for EVERY leg
    (autonomous AND interactive) — the cross-cutting discipline the hunter carries at all times."""

    PROJ = TestAutonomousRoeFullPipeline.PROJ

    def _assert_discipline(self, t):
        # section header (demoted from the contract file's standalone H1 to an `##` section)
        self.assertIn("## Engagement discipline", t)
        # the cross-cutting anti-patterns
        self.assertIn("Reflection is not execution", t)
        self.assertIn("two distinct identities", t)              # IDOR/BOLA
        self.assertIn("WAF/403", t)                              # path EXISTS != finding
        self.assertIn("SIGNAL, not a finding", t)                # behaviour divergence
        self.assertIn("attributable OOB callback or controlled timing", t)  # blind bugs
        self.assertIn("Benign PoC only", t)                      # defer destructive to the gate
        self.assertIn("chained or ruled out", t)                 # feeder-class discipline

    def test_discipline_present_autonomous(self):
        t = roe.render_roe(self.PROJ, "acme-2026-11-16", autonomous=True)
        self._assert_discipline(t)

    def test_discipline_present_interactive(self):
        # always-on: present even with NO autonomous note
        t = roe.render_roe(self.PROJ, "eid", autonomous=False)
        self._assert_discipline(t)
        self.assertNotIn("AUTONOMOUS run", t)

    def test_authorization_spine_intact(self):
        # the discipline block must NOT disturb the §0 "authorization recorded, do not re-ask" spine
        t = roe.render_roe(self.PROJ, "eid", autonomous=False)
        self.assertIn("ALREADY ESTABLISHED (do not re-ask)", t)
        self.assertIn("SATISFIED", t)
        self.assertNotIn("{discipline}", t)  # f-string placeholder fully substituted

    def test_discipline_falls_back_when_file_unreadable(self):
        # if the contract file can't be read, the terse inline fallback still carries the block
        with mock.patch.object(roe, "_DISCIPLINE_PATH",
                               pathlib.Path("/no/such/engagement-discipline.md")):
            t = roe.render_roe(self.PROJ, "eid", autonomous=False)
        self.assertIn("## Engagement discipline", t)
        self.assertIn("Reflection is not execution", t)


class TestSeedNotebook(unittest.TestCase):
    def test_seed_notebook_invokes_notebook_plan(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "scripts").mkdir()
            script = repo / "scripts" / "notebook.py"
            script.write_text("# stub\n", encoding="utf-8")
            eng = repo / "engagements" / "acme"
            eng.mkdir(parents=True)

            captured = {}

            def fake_run(argv, *a, **kw):
                captured["argv"] = argv
                return None

            with mock.patch.object(launch.subprocess, "run", side_effect=fake_run):
                launch._seed_notebook(eng, repo, "py")

            self.assertEqual(
                captured["argv"],
                ["py", str(script), "--plan", "--engagement", str(eng)],
            )

    def test_seed_notebook_skips_when_already_present(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "scripts").mkdir()
            (repo / "scripts" / "notebook.py").write_text("# stub\n", encoding="utf-8")
            eng = repo / "eng"
            eng.mkdir()
            (eng / "notebook.json").write_text("{}", encoding="utf-8")  # already seeded
            with mock.patch.object(launch.subprocess, "run") as run:
                launch._seed_notebook(eng, repo, "py")
            run.assert_not_called()

    def test_seed_notebook_skips_when_script_absent(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng = repo / "eng"
            eng.mkdir()
            with mock.patch.object(launch.subprocess, "run") as run:
                launch._seed_notebook(eng, repo, "py")
            run.assert_not_called()

    def test_prepare_runtime_calls_seed_notebook(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
            engagement.scaffold(repo, fields, operator="t")
            eng = repo / "engagements" / fields["engagement"]
            with mock.patch.object(launch, "_seed_notebook") as seed:
                launch.prepare_runtime(eng, repo, "py", mode="autonomous", extra_allow=["Bash(nmap *)"])
            seed.assert_called_once()
            args = seed.call_args.args
            self.assertEqual(args[0], eng.resolve())
            self.assertEqual(args[1], repo)
            self.assertEqual(args[2], "py")


class TestModelRoutingArgv(unittest.TestCase):
    """#3 model routing: --model / --shard-models are plumbed into the built argv; omitted by default."""

    def _prep(self, repo):
        fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
        engagement.scaffold(repo, fields, operator="t")
        eng = repo / "engagements" / fields["engagement"]
        return launch.prepare_runtime(eng, repo, "py", mode="autonomous", extra_allow=["Bash(nmap *)"])

    def test_model_and_shards_before_allowedtools(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            prep = self._prep(repo)
            allowed = ["Read", "WebFetch"]
            argv = launch.build_autonomous_argv(
                "claude", repo, prep, "go", allowed, max_turns=10, max_budget=1.0,
                model="claude-opus-x", shard_models=["a", "b"],
            )
            self.assertEqual(argv[argv.index("--model") + 1], "claude-opus-x")
            self.assertEqual(argv[argv.index("--shard-models") + 1], "a,b")
            at = argv.index("--allowedTools")  # stays last, consuming the allowlist
            self.assertLess(argv.index("--model"), at)
            self.assertLess(argv.index("--shard-models"), at)
            self.assertEqual(argv[at + 1:], allowed)

    def test_defaults_omit_both_flags(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            prep = self._prep(repo)
            base = launch.build_autonomous_argv("claude", repo, prep, "go", ["Read"],
                                                max_turns=10, max_budget=1.0)
            self.assertNotIn("--model", base)          # no flag => claude keeps the global default
            self.assertNotIn("--shard-models", base)

    def test_shard_models_string_is_normalized(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            prep = self._prep(repo)
            argv = launch.build_autonomous_argv("claude", repo, prep, "go", ["Read"],
                                                max_turns=10, max_budget=1.0, shard_models=" a , ,b ")
            self.assertEqual(argv[argv.index("--shard-models") + 1], "a,b")  # trimmed + blanks dropped
            # empty / blank spec omits the flag entirely
            argv2 = launch.build_autonomous_argv("claude", repo, prep, "go", ["Read"],
                                                 max_turns=10, max_budget=1.0, shard_models="  , ")
            self.assertNotIn("--shard-models", argv2)

    def test_interactive_build_argv_model(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
            engagement.scaffold(repo, fields, operator="t")
            eng = repo / "engagements" / fields["engagement"]
            prep = launch.prepare_runtime(eng, repo, "py")
            argv = launch.build_argv("claude", repo, prep, "do it", "default", model="claude-x")
            self.assertEqual(argv[argv.index("--model") + 1], "claude-x")
            self.assertNotIn("--model", launch.build_argv("claude", repo, prep, "do it", "default"))


class TestGatePolicyAlwaysDefer(unittest.TestCase):
    def test_gate_policy_writes_always_defer_tokens(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
            engagement.scaffold(repo, fields, operator="t")
            eng = repo / "engagements" / fields["engagement"]
            launch.prepare_runtime(eng, repo, "py", mode="autonomous", extra_allow=["Bash"])
            policy = json.loads((eng / "runtime" / "gate-policy.json").read_text(encoding="utf-8"))
            self.assertIn("always_defer_tokens", policy)
            self.assertEqual(policy["always_defer_tokens"], sorted(settings._ACTIVE_EXPLOIT_TOKENS))
            self.assertIn("sqlmap", policy["always_defer_tokens"])
            # bash_allow still carries the broad pass-glob from `Bash`
            self.assertEqual(policy["bash_allow"], ["*"])


if __name__ == "__main__":
    unittest.main()
