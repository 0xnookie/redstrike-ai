"""`redstrike` — launch Claude Code as a scoped, gated pentest engine.

Subcommands: doctor | init | run | verify | status | version.
v1 is interactive and human-gated; autonomous headless (-p) is a later milestone.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from . import __version__, accounts, diagnostics, engagement, gate, launch, preflight, reasoning_trace, runloop, source_audit, ui
from . import approvals as approvalsmod
from . import engines as enginesmod
from . import scope as scopemod
from . import settings as settingsmod


def _is_repo(p: Path) -> bool:
    return (p / "skills" / "_contract" / "verify_completion.py").is_file()


def repo_root(override: str | None = None) -> Path | None:
    """Locate the redstrike-ai repo: explicit flag > env > cwd-walk > in-repo package.

    Returns None when installed out-of-tree and none of those resolve (the caller then
    asks for --repo / REDSTRIKE_REPO) — never a bogus venv/site-packages path.
    """
    if override:
        return Path(override).resolve()
    env = os.environ.get("REDSTRIKE_REPO")
    if env:
        return Path(env).resolve()
    here = Path.cwd().resolve()
    for p in [here, *here.parents]:
        if _is_repo(p):
            return p
    cand = Path(__file__).resolve().parents[2]  # editable / in-repo (PYTHONPATH=cli)
    return cand if _is_repo(cand) else None


def _operator() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def _force_utf8() -> None:
    """Emit UTF-8 regardless of console codepage (prevents Windows mojibake/crashes)."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def resolve_engagement(repo: Path, arg: str) -> Path | None:
    p = Path(arg)
    if p.is_dir():
        return p.resolve()
    cand = repo / "engagements" / arg
    if cand.is_dir():
        return cand.resolve()
    return None


# --- commands --------------------------------------------------------------
def cmd_version(args, repo: Path) -> int:
    if not args.no_banner:
        ui.print_banner(f"authorized offensive security  ·  engine: Claude Code  ·  v{__version__}")
    cb = preflight.find_claude()
    v = preflight.claude_version(cb) if cb else None
    print(ui.kv("redstrike", __version__))
    print(ui.kv("claude", (".".join(map(str, v)) if v else "not found")))
    print(ui.kv("repo", str(repo) if repo else "not located (pass --repo / set REDSTRIKE_REPO)"))
    return 0


def cmd_doctor(args, repo: Path) -> int:
    # Machine-readable toolchain capability snapshot. Probes the REAL execution environment (WSL on
    # Windows) for each recon/web capability's primary + fallbacks and reports ok|degraded. With
    # --engagement it ALSO writes that engagement's runtime/tooling.json (the per-engagement record
    # the launch path writes automatically). Exit non-zero when any capability is degraded.
    if args.json:
        snap = preflight.tooling_snapshot(repo)
        if args.engagement:
            eng = resolve_engagement(repo, args.engagement)
            if not eng:
                print(ui.err(f"engagement '{args.engagement}' not found under {repo / 'engagements'}"))
                return 1
            preflight.write_tooling(eng, snap)
        print(json.dumps(snap, indent=2))
        return 0 if snap.get("overall", {}).get("status") == "ok" else 1

    if not args.no_banner:
        ui.print_banner("preflight — engine, auth, platform, tools")
    print(ui.rule("launcher preflight"))
    try:
        engine = enginesmod.get_engine(args.engine, allow_ungated=True)  # doctor reports any engine
    except KeyError as e:
        print(ui.err(str(e)))
        return 2
    gating = "" if engine.supports_tool_gating else "  (no fail-closed gating — lab/offline only)"
    print(ui.kv("engine", f"{engine.name}{gating}"))
    print(ui.kv("engines", "live-safe: " + (", ".join(enginesmod.available()) or "none")))
    try:
        checks = engine.preflight(repo)
    except NotImplementedError:
        print(ui.warn(f"engine '{engine.name}' preflight not implemented yet — skipping engine checks"))
        checks = []
    render = {"ok": ui.ok, "warn": ui.warn, "err": ui.err}
    for c in checks:
        print(render[c.level](f"{c.label:<12} {c.detail}"))
    blocking = preflight.blocking(checks)

    forward: list[str] = []
    if args.env:
        forward.append("--env")
    if args.core:
        forward.append("--core")
    if args.all_cats:
        forward.append("--all")
    if args.missing:
        forward.append("--missing")
    forward += args.categories

    print()
    print(ui.rule("tool roster (scripts/doctor.sh)"))
    rc, out = preflight.run_doctor(repo, forward or None)
    print(out)

    if blocking:
        print(ui.err(f"{len(blocking)} blocking issue(s) — fix before `redstrike run`."))
        return 1
    return rc


def cmd_install(args, repo: Path) -> int:
    if not args.no_banner:
        ui.print_banner("install the offensive tool roster")
    script = repo / "scripts" / "install.sh"
    bash = preflight.find_bash()
    if not script.is_file():
        print(ui.err(f"scripts/install.sh not found at {script}"))
        return 2
    if not bash:
        print(ui.err("bash not found — run scripts/install.sh on a Linux/WSL2 host"))
        return 127
    forward: list[str] = []
    if args.core:
        forward.append("--core")
    if args.all_cats:
        forward.append("--all")
    if args.dry_run:
        forward.append("--dry-run")
    if args.yes:
        forward.append("--yes")
    forward += args.categories
    print(ui.info("scripts/install.sh " + (" ".join(forward) or "(default: --core)")))
    print(ui.warn("installs via apt/pipx/go/… and may use sudo · Kali/Debian/Parrot (WSL2 on Windows)"))
    print()
    rc = preflight.exec_live([bash, str(script), *forward], cwd=str(repo))
    print()
    print(ui.info("re-check with: redstrike doctor"))
    return rc


def _collect_init_fields(args) -> dict:
    domains = list(args.domain or [])
    authorized_by = args.authorized_by
    confirmed = args.i_confirm_authorization

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if interactive and (not authorized_by or not domains):
        print(ui.rule("authorization & scope intake"))
        authorized_by = authorized_by or _ask("  authorized_by (contact + written-auth reference): ")
        if not domains:
            raw = _ask("  in-scope domains (space/comma separated): ")
            domains = [d for d in raw.replace(",", " ").split() if d]
    if not authorized_by:
        raise SystemExit(ui.err("missing --authorized-by (who authorized this test)"))
    if not domains and not (args.cidr or args.url):
        raise SystemExit(ui.err("no in-scope target — pass --domain/--cidr/--url"))

    if not confirmed:
        if interactive:
            ans = _ask(
                "\n  Confirm: written authorization for this scope is on file and the window is valid? [y/N] "
            ).lower()
            confirmed = ans in ("y", "yes")
        if not confirmed:
            raise SystemExit(
                ui.err("authorization NOT confirmed — refusing to scaffold (pass --i-confirm-authorization).")
            )

    return engagement.build_fields(
        client=args.client,
        authorized_by=authorized_by,
        domains=domains,
        cidrs=args.cidr,
        urls=args.url,
        exclude_domains=args.exclude_domain,
        exclude_cidrs=args.exclude_cidr,
        rate_limit=args.rate_limit,
        oob=args.oob or "",
        window=engagement.default_window(args.window_days),
        notes=args.notes,
    )


def cmd_init(args, repo: Path) -> int:
    if not args.no_banner:
        ui.print_banner("new engagement")
    fields = _collect_init_fields(args)
    try:
        eng_dir = engagement.scaffold(repo, fields, operator=_operator(), force=args.force)
    except FileExistsError as e:
        print(ui.err(str(e)))
        return 1
    print(ui.ok(f"engagement scaffolded: {eng_dir.relative_to(repo)}"))
    print(ui.kv("scope", str((eng_dir / "scope.yaml").relative_to(repo))))
    print(ui.kv("authz", fields["authorized_by"]))
    print(ui.kv("in-scope", ", ".join(fields["in_scope"]["domains"]) or "—"))
    print(ui.kv("window", f"{fields['window']['start']} .. {fields['window']['end']}"))
    print()
    print(ui.info(f"review scope.yaml, then: redstrike run {eng_dir.name}"))
    return 0


def cmd_audit(args, repo: Path) -> int:
    """Paste a repo URL → a white-box source-audit engagement. Clone the repo (shallow, untrusted —
    no code executed) into engagements/<id>/source/, scaffold a source-granted scope.yaml carrying
    the shared `source:` block + the authorization record, then launch the run the SAME way
    `redstrike run` does (unless --no-launch). Mirrors `init`'s authorization gate."""
    if not args.no_banner:
        ui.print_banner("white-box source audit")

    # 1) Validate/normalize the URL up front — fail before any prompt or filesystem work.
    try:
        url = source_audit.normalize_url(args.repo_url)
    except ValueError as e:
        print(ui.err(f"invalid repository URL: {e}"))
        return 2

    # 2) Authorization gate (same assertion the init flow records).
    authorized_by = args.authorized_by
    confirmed = args.i_confirm_authorization
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if interactive and not authorized_by:
        print(ui.rule("authorization & scope intake"))
        authorized_by = _ask("  authorized_by (contact + written-auth reference): ")
    if not authorized_by:
        print(ui.err("missing --authorized-by (who authorized this source audit)"))
        return 2
    if not confirmed:
        if interactive:
            ans = _ask(
                "\n  Confirm: written authorization to audit this source is on file and the window is valid? [y/N] "
            ).lower()
            confirmed = ans in ("y", "yes")
        if not confirmed:
            print(ui.err("authorization NOT confirmed — refusing to clone/scaffold (pass --i-confirm-authorization)."))
            return 2

    # 3) Resolve the engagement id + dir; refuse to clobber an existing one unless --force.
    client = args.client or source_audit.repo_name_from_url(url)
    eid = engagement.engagement_id(client)
    eng_dir = repo / "engagements" / eid
    source_dir = eng_dir / "source"
    if (eng_dir / "scope.yaml").exists() and not args.force:
        print(ui.err(f"engagement already exists: {eng_dir.relative_to(repo)} (use --force to overwrite)"))
        return 1

    # 4) Clone the (untrusted) repo. Only this invocation's fresh artifacts are cleaned up on failure.
    created_dir = not eng_dir.exists()
    if args.force and source_dir.exists():
        source_audit.rmtree_safe(source_dir)
    eng_dir.mkdir(parents=True, exist_ok=True)
    print(ui.info(f"cloning {url} → {source_dir.relative_to(repo)}  (shallow · untrusted · no code executed)…"))
    try:
        info = source_audit.clone(url, source_dir, branch=args.branch, timeout=args.clone_timeout)
    except source_audit.CloneError as e:
        # Surface the failure (never a silent no-op) and remove only what this run created.
        print(ui.err(f"clone failed: {e}"))
        source_audit.rmtree_safe(eng_dir if created_dir else source_dir)
        return 1
    print(ui.ok(f"cloned · commit {info['commit'][:12]} · branch {info['branch'] or '(detached)'}"))

    # 5) Scaffold the source-granted scope.yaml. The repo URL is recorded as the in-scope target so
    #    the shared launch gate (authorization + a target + a window) is satisfied unchanged.
    source_block = source_audit.build_source_block(url, "source/", info["commit"], info["branch"])
    fields = engagement.build_fields(
        client=client,
        authorized_by=authorized_by,
        domains=[],
        urls=[url],
        window=engagement.default_window(args.window_days),
        source=source_block,
        notes="White-box source audit of the cloned repository. Written authorization on file before the window opens.",
    )
    try:
        engagement.scaffold(repo, fields, operator=_operator(), force=args.force)
    except FileExistsError as e:
        print(ui.err(str(e)))
        # Don't leave this run's clone behind to wedge the next `redstrike audit` of the same repo.
        source_audit.rmtree_safe(eng_dir if created_dir else source_dir)
        return 1
    print(ui.ok(f"source-granted engagement scaffolded: {eng_dir.relative_to(repo)}"))
    print(ui.kv("scope", str((eng_dir / "scope.yaml").relative_to(repo))))
    print(ui.kv("authz", authorized_by))
    print(ui.kv("source", f"{url} @ {info['commit'][:12]} ({info['branch'] or 'detached'})"))
    print(ui.kv("local", str(source_dir.relative_to(repo))))
    print(f"engagement_id={eid}")   # machine-readable id for the control plane (plain, no ANSI)

    if args.no_launch:
        print()
        print(ui.info(f"review scope.yaml, then: redstrike run {eid}"))
        return 0

    # 6) Launch via the SAME mechanism as `redstrike run` (interactive gated, or --autonomous).
    print()
    args.engagement = eid
    return cmd_run(args, repo)


def _console_requested(args) -> bool:
    if getattr(args, "console", False):
        return True
    return os.environ.get("REDSTRIKE_CONSOLE", "").strip().lower() in ("1", "true", "yes", "on")


def maybe_launch_console(args, repo: Path) -> None:
    """After a run, optionally bring up the console (idempotent — reuses a running one)."""
    if _console_requested(args):
        print()
        print(ui.ok("bringing up the web console over engagements/ …"))
        launch.launch_console(repo, port=getattr(args, "console_port", 8787))
    else:
        print("  tip: view results in the web console — `redstrike console`")


def _warn_scope_integrity(prep) -> None:
    """Surface a scope.yaml drift (vs the fingerprint acknowledged at init) before launch."""
    w = getattr(prep, "scope_integrity_warning", "")
    if w:
        print(ui.warn(w))


def _warn_no_sandbox() -> None:
    """Promote the 'no OS sandbox / network confinement OFF' check to a visible banner on the run
    path (not just buried in `doctor`): without the OS sandbox, the scope gate is the only boundary."""
    ok, detail = preflight.sandbox_status()
    if not ok:
        print()
        print(ui.rule("network confinement"))
        print(ui.warn(detail))
        print()


def _prelaunch_artifacts(eng_dir: Path, repo: Path) -> None:
    """At hunt start, produce the derived launch artifacts the executors depend on but that nothing
    else writes. Called ONCE from `cmd_run` before the interactive/autonomous split, so it covers
    BOTH modes:
      • materialize `runtime/auth.env` from the stored test-account creds, so a registered 2nd
        identity actually reaches the executors (every skill reference to auth.env is a READER);
      • snapshot the REAL toolchain (WSL on Windows) into `runtime/tooling.json`, so a missing recon
        primary (httpx/dnsx/subfinder/naabu) that silently falls back to nmap/dig is a recorded
        health NOTE the diagnostics outcome can read, not an invisible degradation.
    Best-effort: a failure here never blocks a launch and never prints a secret."""
    try:
        n = accounts.account_count(eng_dir)
        p = accounts.materialize(eng_dir)
        if p is not None:
            print(ui.ok(f"auth.env materialized for the executors ({n} "
                        f"identit{'y' if n == 1 else 'ies'}) · {p}"))
    except Exception:
        pass
    try:
        snap = preflight.tooling_snapshot(repo)
        path = preflight.write_tooling(eng_dir, snap)
        ov = snap.get("overall", {})
        if ov.get("status") == "degraded":
            dc = ov.get("degraded_count", 0)
            print(ui.warn(f"toolchain degraded: {dc} recon capabilit{'y' if dc == 1 else 'ies'} "
                          f"missing their primary (fallback in use) — see {path}"))
        else:
            print(ui.ok(f"toolchain ok — recon primaries present · {path}"))
    except Exception:
        pass


def _post_run_gate(repo: Path, eng_dir: Path, res, *, prep=None, mode: str = "interactive",
                   loop=None) -> int:
    """Run the mechanical completion + coverage gate after an engine run, then write the per-run
    diagnostics record and surface the OUTCOME. The engine itself can't self-gate between phases,
    so this is where the gates become mechanical rather than model-discretion. If the engine exited
    clean (rc 0) but the gate flags gaps (malformed findings, missing evidence, a category left
    `pending`), surface it in the exit code so an unattended caller sees the failure; a non-zero
    engine rc is left as-is.

    For an autonomous looped run this runs ONCE after the whole loop: ``res`` reflects the whole run
    (last leg's summary + cumulative cost + first→last bounds) and ``loop`` carries the loop's stop
    reason so the diagnostics outcome is honest (completed vs budget-truncated vs blocked).

    ``res`` is the engine's ``RunResult`` (an int is still tolerated for back-compat)."""
    rc = getattr(res, "rc", res)
    print()
    print(ui.rule("post-run gate"))
    grc = gate.verify(repo, eng_dir)
    if grc == 0:
        print(ui.ok("gate clear — findings well-formed, category coverage accounted for"))
    elif rc == 0:
        print(ui.warn("engine exited clean, but the completion/coverage gate flagged gaps (above) — not report-ready"))
    # Diagnostics (reliability/observability): classify WHY this run produced what it did and record
    # it — for INTERACTIVE runs too (they captured nothing before). Must never alter the exit code.
    try:
        _emit_diagnostics(eng_dir, res, prep=prep, mode=mode, gate_rc=grc, loop=loop)
    except Exception:
        pass
    # Reasoning-provenance trace (runtime/reasoning_trace.json): a persisted, entity-keyed lineage of
    # HOW findings came to be (goal -> intent/hypothesis -> fact/evidence -> finding), for the console's
    # exploration graph. Strictly additive + crash-safe; a failure degrades (one warning) but never
    # alters the exit code or aborts the run.
    _emit_reasoning_trace(eng_dir)
    if grc != 0 and rc == 0:
        return grc
    return rc


def _emit_reasoning_trace(eng_dir: Path) -> None:
    """Derive + persist the reasoning-provenance trace. Best-effort: a write error is SURFACED (a
    warning, never a silent no-op per the diagnostics discipline) but is non-fatal — the run and the
    graph work without it."""
    try:
        trace = reasoning_trace.assemble(eng_dir)
        path = reasoning_trace.write(eng_dir, trace)
        n_find = sum(1 for n in trace.get("nodes", []) if n.get("kind") == reasoning_trace.FINDING)
        print(ui.info(f"reasoning trace: {path}  ({len(trace.get('nodes', []))} nodes · {n_find} findings)"))
    except Exception as exc:  # noqa: BLE001 — surface, don't abort
        print(ui.warn(f"reasoning trace: could not write runtime/reasoning_trace.json ({exc}) — "
                      f"the exploration-graph provenance overlay will be absent this run"))


def _emit_diagnostics(eng_dir: Path, res, *, prep, mode: str, gate_rc: int, loop=None) -> None:
    summary = getattr(res, "summary", None)
    if isinstance(summary, str):  # the empty-string default == no captured summary (interactive)
        summary = None
    record = diagnostics.assemble(
        eng_dir,
        session=getattr(prep, "session_id", "") if prep else "",
        mode=mode,
        started=getattr(res, "started", ""),
        ended=getattr(res, "ended", ""),
        engine_rc=getattr(res, "rc", 0),
        gate_rc=gate_rc,
        summary=summary,
    ).to_record()
    # Overlay the whole-run loop outcome so a budget-truncated / stuck / blocked autonomous run is
    # recorded as degraded-with-a-reason (coverage partial), never silently "clean".
    if loop is not None:
        record = runloop.annotate_record(record, loop)
    diagnostics.write(eng_dir, record)
    _print_outcome(eng_dir, record)


def _print_outcome(eng_dir: Path, record: dict) -> None:
    """Prominent CLI block: the OUTCOME, and — when not healthy — WHY it produced nothing plus the
    transport-health line, so an empty engagement is never silently indistinguishable from a clean one."""
    outcome = record.get("outcome", "")
    healthy = outcome in (diagnostics.PRODUCED, diagnostics.CLEAN)
    print()
    print(ui.rule("outcome diagnostics"))
    line = f"OUTCOME: {outcome}"
    print((ui.ok if healthy else ui.warn)(line))
    if not healthy and record.get("degraded_reason"):
        print(ui.warn(f"produced nothing because: {record['degraded_reason']}"))
    overall = (record.get("transport_health") or {}).get("overall") or {}
    if overall.get("status") in ("degraded", "blocked"):
        worst = overall.get("worst_host") or "the target"
        pct = round(float(overall.get("block_rate", 0.0) or 0.0) * 100)
        waf = diagnostics._worst_host_waf(record.get("transport_health") or {}, overall.get("worst_host"))
        tail = f" ({waf})" if waf else ""
        print(ui.warn(f"{pct}% of requests to {worst} blocked/challenged{tail} — coverage UNRELIABLE"))
    print(ui.info(f"diagnostics: {eng_dir / 'runtime' / 'diagnostics.json'}  (+ error.log)"))


def cmd_console(args, repo: Path) -> int:
    target = repo / "engagements"
    if args.engagement:
        eng = resolve_engagement(repo, args.engagement)
        if not eng:
            print(ui.err(f"engagement '{args.engagement}' not found"))
            return 1
        target = eng
    if not args.no_banner:
        ui.print_banner("console")
    argv = launch.launch_console(
        repo, target=target, port=args.port,
        background=args.background, open_browser=not args.no_open, dry_run=args.dry_run,
    )
    if args.dry_run:
        print("  " + " ".join(shlex.quote(a) for a in argv))
    return 0


def cmd_run(args, repo: Path) -> int:
    eng_dir = resolve_engagement(repo, args.engagement)
    if not eng_dir:
        print(ui.err(f"engagement '{args.engagement}' not found under {repo / 'engagements'}"))
        return 1
    try:
        engine = enginesmod.get_engine(args.engine)
    except (KeyError, RuntimeError) as e:
        print(ui.err(str(e)))
        return 2
    if not args.no_banner:
        suffix = "  ·  AUTONOMOUS" if args.autonomous else ""
        if engine.name != enginesmod.DEFAULT_ENGINE:
            suffix += f"  ·  engine: {engine.name}"
        ui.print_banner(f"engagement {eng_dir.name}" + suffix)

    _warn_no_sandbox()
    # Hunt-start artifacts (auth.env materialize + toolchain snapshot) for BOTH modes — runs here,
    # before the autonomous split, since _run_autonomous is reached only through this path.
    _prelaunch_artifacts(eng_dir, repo)

    if args.autonomous:
        return _run_autonomous(args, repo, eng_dir, engine)

    try:
        prep = engine.prepare(eng_dir, repo, sys.executable)
    except FileNotFoundError as e:
        print(ui.err(str(e)))
        return 1

    for line in scopemod.summary_lines(prep.scope):
        print(f"  {line}")
    _warn_scope_integrity(prep)

    problems = engine.gate(prep)
    if problems:
        print()
        for p in problems:
            print(ui.err(p))
        print(ui.err("launch blocked (fail-closed). Fix scope.yaml / window and re-run."))
        return 2

    prompt = args.prompt or launch.default_prompt(prep.engagement_id)
    # Per-run model override is passed only when given, so an engine adapter without the kwarg (e.g. a
    # test double) is unaffected when no --model is set — preserving the no-flag default behavior.
    inv_kwargs = {"mode": "interactive", "permission_mode": args.permission_mode}
    if getattr(args, "model", None):
        inv_kwargs["model"] = args.model
    inv = engine.build_invocation(prep, repo, prompt, **inv_kwargs)
    available = engine.is_available()

    if args.dry_run or not available:
        print()
        print(ui.rule("DRY RUN — generated runtime artifacts"))
        for label, val in engine.runtime_artifacts(prep, repo):
            print(ui.kv(label, val))
        print()
        print(ui.rule("would exec"))
        print("  " + " ".join(shlex.quote(a) for a in inv.argv))
        if not available and not args.dry_run:
            print()
            print(ui.err(f"`{engine.name}` engine not available on PATH — printed the plan instead of launching."))
            return 127
        return 0

    authed, detail = engine.auth_status()
    if authed is False:
        print(ui.err(f"{engine.name} not authenticated: {detail}"))
        return 1
    print()
    print(ui.ok(f"scope gate armed · launching {engine.name} engine (interactive, gated)…"))
    print()
    audit = eng_dir / "runtime" / "autorun.jsonl"  # audit the interactive run too (stamped head + footer)
    res = engine.run(prep, eng_dir, inv, mode="interactive", audit=audit)
    rc = _post_run_gate(repo, eng_dir, res, prep=prep, mode="interactive")
    maybe_launch_console(args, repo)
    return rc


def _run_autonomous(args, repo: Path, eng_dir: Path, engine) -> int:
    extra_allow = args.allow or []
    try:
        prep = engine.prepare(
            eng_dir, repo, sys.executable, mode="autonomous", extra_allow=extra_allow,
            resume=args.resume,
        )
    except FileNotFoundError as e:
        print(ui.err(str(e)))
        return 1

    for line in scopemod.summary_lines(prep.scope):
        print(f"  {line}")
    _warn_scope_integrity(prep)
    # Flag --allow globs broad enough to run active-exploit commands with no per-command deferral,
    # i.e. that would bypass the autonomous approval gate for the highest-impact classes.
    for w in settingsmod.broad_allow_warnings(extra_allow):
        print(ui.warn(w))
    problems = engine.gate(prep)
    if problems:
        print()
        for p in problems:
            print(ui.err(p))
        print(ui.err("launch blocked (fail-closed). Fix scope.yaml / window and re-run."))
        return 2

    prompt = args.prompt
    if args.resume and not prompt:
        queue = approvalsmod.take_resume_queue(prep.approvals_path)
        if queue:
            cmds = "\n".join(f"- {e.get('command') or e.get('summary')}" for e in queue)
            prompt = (
                "The operator has APPROVED these previously-deferred actions. Re-issue each one now, "
                "exactly as written, using the appropriate tool, then continue the engagement:\n"
                f"{cmds}"
            )
        else:
            prompt = "Continue the engagement from where it was paused."
    if not prompt:
        prompt = launch.autonomous_prompt(prep.engagement_id)

    inv = engine.build_invocation(
        prep, repo, prompt, mode="autonomous", allow=extra_allow,
        max_turns=args.max_turns, max_budget=args.max_budget_usd, resume=args.resume,
        model=getattr(args, "model", None), shard_models=getattr(args, "shard_models", None),
    )
    available = engine.is_available()

    if args.dry_run or not available:
        print()
        print(ui.rule("DRY RUN — autonomous argv"))
        print(ui.kv("allowlist", " ".join(inv.allowed or [])))
        print(ui.kv("caps", f"max_turns={args.max_turns}  budget=${args.max_budget_usd}"))
        _sm = getattr(args, "shard_models", None)
        print(ui.kv("model", (getattr(args, "model", None) or "(global default / ANTHROPIC_MODEL)")
                             + (f"  ·  shards: {_sm}" if _sm else "")))
        print("  " + " ".join(shlex.quote(a) for a in inv.argv))
        if not available and not args.dry_run:
            print(ui.err(f"`{engine.name}` engine not available on PATH — printed the plan instead of launching."))
            return 127
        return 0

    authed, detail = engine.auth_status()
    if authed is False:
        print(ui.err(f"{engine.name} not authenticated: {detail}"))
        return 1
    print()
    print(ui.ok(
        f"scope gate armed · autonomous headless run (dontAsk, per-invocation max_turns="
        f"{args.max_turns}, total budget=${args.max_budget_usd})…"
    ))
    print()
    # The autonomous run is a LOOP: one process spawns many resumed engine invocations until the
    # engagement is report-ready or a ceiling trips. Running in THIS process keeps the console's
    # pid-liveness + autorun.jsonl boundary-marker contract intact. The post-run gate + diagnostics
    # run ONCE, after the loop, over the whole-run result.
    audit = eng_dir / "runtime" / "autorun.jsonl"
    # Wave-2 (2b) dispatch: >1 shard-model ⇒ the concurrent multi-process worker pool (one shard per model,
    # fanned out per wave); otherwise the single-session resumer, UNCHANGED (no / one shard-model is
    # byte-for-byte the legacy path). See runloop.shard_model_list / drive_pool.
    shards = runloop.shard_model_list(getattr(args, "shard_models", None))
    if len(shards) > 1:
        print(ui.ok(f"concurrent hunt pool · {len(shards)} shards: {', '.join(shards)}"))
        loop = runloop.drive_pool(
            engine, prep, repo, eng_dir,
            first_prompt=prompt,
            extra_allow=extra_allow,
            max_turns=args.max_turns,
            max_budget_usd=args.max_budget_usd,
            first_resume=bool(args.resume),
            audit=audit,
            engagement_id=prep.engagement_id,
            shard_models=shards,
        )
    else:
        loop = runloop.drive(
            engine, prep, repo, eng_dir,
            first_prompt=prompt,
            extra_allow=extra_allow,
            max_turns=args.max_turns,
            max_budget_usd=args.max_budget_usd,
            first_resume=bool(args.resume),
            audit=audit,
            engagement_id=prep.engagement_id,
        )
    rc = _post_run_gate(repo, eng_dir, loop.result, prep=prep, mode="autonomous", loop=loop)
    maybe_launch_console(args, repo)
    return rc


def cmd_approve(args, repo: Path) -> int:
    eng_dir = resolve_engagement(repo, args.engagement)
    if not eng_dir:
        print(ui.err(f"engagement '{args.engagement}' not found"))
        return 1
    if not args.no_banner:
        ui.print_banner(f"approvals · {eng_dir.name}")
    pending_path = eng_dir / "runtime" / "approvals_pending.json"
    approvals_path = eng_dir / "runtime" / "approvals.json"
    pending = approvalsmod.list_pending(pending_path)
    if not pending:
        print(ui.info("no pending deferrals — nothing to approve"))
        return 0

    print(ui.rule("pending deferrals (autonomous)"))
    for p in pending:
        print(f"  {ui.style(p['fingerprint'][:12], ui.YELLOW)}  {p.get('summary', '')[:100]}")
    if args.list:
        return 0

    chosen: set[str] = set()
    if args.all:
        chosen = {p["fingerprint"] for p in pending}
    elif args.id:
        for want in args.id:
            chosen |= {p["fingerprint"] for p in pending if p["fingerprint"].startswith(want)}
    elif sys.stdin.isatty():
        print()
        for p in pending:
            ans = _ask(f"  approve [{p['fingerprint'][:12]}] {p.get('summary', '')[:70]} ? [y/N] ").lower()
            if ans in ("y", "yes"):
                chosen.add(p["fingerprint"])
    else:
        print(ui.err("non-interactive: pass --all, --id <fingerprint>, or --list"))
        return 2

    if not chosen:
        print(ui.warn("nothing approved"))
        return 0
    moved = approvalsmod.approve(approvals_path, pending_path, chosen)
    print(ui.ok(f"approved {len(moved)} action(s) — the scope gate will let them run on resume"))
    print(ui.info(f"continue: redstrike run {eng_dir.name} --autonomous --resume"))
    return 0


def cmd_verify(args, repo: Path) -> int:
    eng_dir = resolve_engagement(repo, args.engagement)
    if not eng_dir:
        print(ui.err(f"engagement '{args.engagement}' not found"))
        return 1
    return gate.verify(repo, eng_dir, skill=args.skill, as_json=args.json)


def cmd_status(args, repo: Path) -> int:
    eng_dir = resolve_engagement(repo, args.engagement)
    if not eng_dir:
        print(ui.err(f"engagement '{args.engagement}' not found"))
        return 1
    return gate.status(repo, eng_dir)


def _parse_headers(raw_list) -> dict:
    out: dict = {}
    for h in raw_list or []:
        k, sep, v = h.partition(":")
        if sep and k.strip():
            out[k.strip()] = v.strip()
    return out


def cmd_accounts(args, repo: Path) -> int:
    """Register/list/remove test-account credentials. Secrets go to runtime/creds.json
    (gitignored, never console-served); a redacted projection is mirrored into the notebook."""
    eng_dir = resolve_engagement(repo, args.engagement)
    if not eng_dir:
        print(ui.err(f"engagement '{args.engagement}' not found under {repo / 'engagements'}"))
        return 1

    if args.action == "materialize":
        n = accounts.account_count(eng_dir)
        p = accounts.materialize(eng_dir)
        if p is None:
            print(ui.info("no test accounts to materialize (runtime/creds.json absent/empty)"))
            return 0
        print(ui.ok(f"materialized runtime/auth.env ({n} identit{'y' if n == 1 else 'ies'}) "
                    f"for the executors"))
        print(ui.kv("auth.env", str(eng_dir / accounts.AUTH_ENV_REL) + "  (gitignored · never served)"))
        return 0

    if args.action == "list":
        rows = accounts.summaries(eng_dir)
        if not rows:
            print(ui.info("no test accounts registered"))
            return 0
        print(ui.rule(f"test accounts · {eng_dir.name}"))
        for r in rows:
            ident = f"  {r['identity']}" if r["identity"] else ""
            print(f"  {ui.style(r['id'], ui.YELLOW)}  {(r['role'] or '—'):<10} "
                  f"{(r['auth'] or '—'):<16} {(r['status'] or '—'):<8} {r['secret']}{ident}")
        print(ui.info(f"secrets: {eng_dir / accounts.CREDS_REL}  (gitignored · never served)"))
        return 0

    if args.action == "rm":
        if not args.id:
            print(ui.err("accounts rm needs --id"))
            return 2
        ok = accounts.remove(eng_dir, args.id)
        if ok:
            # Keep runtime/auth.env in sync with the store; drop it entirely if that was the last id.
            if accounts.materialize(eng_dir) is None:
                accounts.clear_auth_env(eng_dir)
        print(ui.ok(f"removed account '{args.id}'") if ok else ui.warn(f"no account '{args.id}'"))
        return 0 if ok else 1

    # add
    if not args.id:
        print(ui.err("accounts add needs --id"))
        return 2
    headers = _parse_headers(args.header)
    if not (args.password or args.token or args.cookie or headers):
        print(ui.err("accounts add needs a secret: --password / --token / --cookie / --header 'K: V'"))
        return 2
    acct = accounts.build_account(
        id=args.id, role=args.role or "", tenant=args.tenant or "",
        identity=args.identity or "", auth=args.auth or "", status=args.status,
        used_for=args.used_for or "", password=args.password or "", token=args.token or "",
        cookie=args.cookie or "", headers=headers,
    )
    accounts.upsert(eng_dir, acct)
    accounts.materialize(eng_dir)  # keep runtime/auth.env current so the new identity reaches executors
    print(ui.ok(f"account '{args.id}' stored"))
    print(ui.kv("creds", str((eng_dir / accounts.CREDS_REL)) + "  (gitignored · never served)"))
    print(ui.kv("auth.env", "materialized for the executors (gitignored · never served)"))
    print(ui.kv("notebook", "redacted projection written to test_accounts[]"))
    print(ui.kv("role", acct.get("role") or "—"))
    print(ui.kv("auth", acct.get("auth_method") or "—"))
    print(ui.kv("secret", accounts.mask_secret(acct)))
    return 0


# --- parser ----------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="redstrike", description="Run Claude Code as a scoped pentest engine.")
    ap.add_argument("--repo", help="path to the redstrike-ai repo (default: autodetect / $REDSTRIKE_REPO)")
    ap.add_argument("--engine", help="engine backend id (default: $REDSTRIKE_ENGINE or claude-code)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--no-banner", action="store_true", help="suppress the REDSTRIKE banner")
    sub = ap.add_subparsers(dest="command")

    sub.add_parser("version", help="show versions")

    d = sub.add_parser("doctor", help="preflight: engine, auth, platform, tool roster")
    d.add_argument("--env", action="store_true", help="only the runtime-environment preflight")
    d.add_argument("--core", action="store_true", help="core tool categories only")
    d.add_argument("--all", action="store_true", dest="all_cats", help="all tool categories")
    d.add_argument("--missing", action="store_true", help="list only missing tools")
    d.add_argument("--json", action="store_true",
                   help="emit the recon/web toolchain capability snapshot as JSON (probes WSL on Windows)")
    d.add_argument("--engagement", metavar="ENG",
                   help="with --json: also write this engagement's runtime/tooling.json")
    d.add_argument("categories", nargs="*", help="specific tool categories (e.g. web recon ad)")

    ins = sub.add_parser("install", help="install the offensive tool roster (wraps scripts/install.sh)")
    ins.add_argument("--core", action="store_true", help="core set: glue+recon+web+password+intercept (default)")
    ins.add_argument("--all", action="store_true", dest="all_cats", help="every category (large)")
    ins.add_argument("--dry-run", action="store_true", help="print the plan; change nothing")
    ins.add_argument("--yes", action="store_true", help="assume yes / non-interactive")
    ins.add_argument("categories", nargs="*", help="specific categories (e.g. web recon ad cloud)")

    i = sub.add_parser("init", help="scaffold a new engagement + scope.yaml")
    i.add_argument("client")
    i.add_argument("--authorized-by")
    i.add_argument("--domain", action="append", metavar="DOMAIN")
    i.add_argument("--cidr", action="append", metavar="CIDR")
    i.add_argument("--url", action="append", metavar="URL")
    i.add_argument("--exclude-domain", action="append", metavar="DOMAIN")
    i.add_argument("--exclude-cidr", action="append", metavar="CIDR")
    i.add_argument("--window-days", type=int, default=14)
    i.add_argument("--rate-limit", type=int, default=20)
    i.add_argument("--oob", help="OOB collaborator host")
    i.add_argument("--notes")
    i.add_argument("--i-confirm-authorization", action="store_true",
                   help="assert written authorization is on file (required non-interactively)")
    i.add_argument("--force", action="store_true", help="overwrite an existing scope.yaml")

    au = sub.add_parser("audit",
                        help="clone a repo URL into a white-box source-audit engagement, then launch it")
    au.add_argument("repo_url", help="http(s):// or git:// repository URL to audit")
    au.add_argument("--client", help="engagement client/name (default: derived from the repo URL)")
    au.add_argument("--authorized-by", help="who authorized this source audit (contact + written-auth ref)")
    au.add_argument("--branch", help="branch/tag to check out (default: the repo's default branch)")
    au.add_argument("--window-days", type=int, default=14)
    au.add_argument("--clone-timeout", type=int, default=source_audit.DEFAULT_TIMEOUT,
                    help=f"abort the clone after N seconds (default {source_audit.DEFAULT_TIMEOUT})")
    au.add_argument("--i-confirm-authorization", action="store_true",
                    help="assert written authorization is on file (required non-interactively)")
    au.add_argument("--force", action="store_true", help="overwrite an existing engagement of the same id")
    au.add_argument("--no-launch", action="store_true",
                    help="clone + scaffold only; do not launch the run (print the `run` command instead)")
    # run-forwarding flags (audit delegates to the run path after scaffolding — mirror `run`)
    au.add_argument("--dry-run", action="store_true", help="prepare + print the argv; do not launch")
    au.add_argument("--permission-mode", default="default", choices=["default", "plan", "acceptEdits"])
    au.add_argument("--prompt", help="override the initial prompt")
    au.add_argument("--autonomous", "-n", action="store_true",
                    help="headless unattended run (claude -p, dontAsk + allowlist, budget/turn capped)")
    au.add_argument("--allow", action="append", metavar="RULE",
                    help="autonomous: add an allowlist entry, e.g. --allow 'Bash(grep *)' or --allow Bash")
    au.add_argument("--max-turns", type=int, default=200, help="autonomous: hard turn cap (default 200)")
    au.add_argument("--max-budget-usd", type=float, default=20.0, help="autonomous: USD budget cap (default 20)")
    au.add_argument("--resume", action="store_true", help="autonomous: resume the engagement's stored session")
    au.add_argument("--model", metavar="MODEL",
                    help="engine model for this run (default: the global ANTHROPIC_MODEL). "
                         "Route reasoning-heavy work to opus; mechanical/reviewer/recon can run cheaper.")
    au.add_argument("--shard-models", dest="shard_models", metavar="A,B,...",
                    help="comma-separated per-shard models; >1 runs the CONCURRENT multi-process hunt pool "
                         "(one shard per model at once = a cheap diversity pass that raises recall)")
    au.add_argument("--console", action="store_true",
                    help="when the run finishes, bring up the web console over engagements/")
    au.add_argument("--console-port", type=int, default=8787, help="port for --console (default 8787)")

    r = sub.add_parser("run", help="launch the engagement (interactive gated, or --autonomous)")
    r.add_argument("engagement", help="engagement id or path")
    r.add_argument("--dry-run", action="store_true", help="prepare + print the argv; do not launch")
    r.add_argument("--permission-mode", default="default", choices=["default", "plan", "acceptEdits"])
    r.add_argument("--prompt", help="override the initial prompt")
    r.add_argument("--autonomous", "-n", action="store_true",
                   help="headless unattended run (claude -p, dontAsk + allowlist, budget/turn capped)")
    r.add_argument("--allow", action="append", metavar="RULE",
                   help="autonomous: add an allowlist entry, e.g. --allow 'Bash(nmap *)' or --allow Bash")
    r.add_argument("--max-turns", type=int, default=200, help="autonomous: hard turn cap (default 200)")
    r.add_argument("--max-budget-usd", type=float, default=20.0, help="autonomous: USD budget cap (default 20)")
    r.add_argument("--resume", action="store_true", help="autonomous: resume the engagement's stored session")
    r.add_argument("--model", metavar="MODEL",
                   help="engine model for this run (default: the global ANTHROPIC_MODEL). "
                        "Route reasoning-heavy work to opus; mechanical/reviewer/recon can run cheaper.")
    r.add_argument("--shard-models", dest="shard_models", metavar="A,B,...",
                   help="comma-separated per-shard models; >1 runs the CONCURRENT multi-process hunt pool "
                        "(one shard per model at once = a cheap diversity pass that raises recall)")
    r.add_argument("--console", action="store_true",
                   help="when the run finishes, bring up the web console over engagements/ (or set REDSTRIKE_CONSOLE=1)")
    r.add_argument("--console-port", type=int, default=8787, help="port for --console (default 8787)")

    c = sub.add_parser("console", help="open the web console over your engagements")
    c.add_argument("engagement", nargs="?", help="limit to a single engagement (default: all engagements/)")
    c.add_argument("--port", type=int, default=8787)
    c.add_argument("--background", action="store_true", help="detach and return instead of blocking")
    c.add_argument("--no-open", action="store_true", help="do not open a browser")
    c.add_argument("--dry-run", action="store_true", help="print the command and exit")

    v = sub.add_parser("verify", help="run the mechanical gate (verify_completion.py)")
    v.add_argument("engagement")
    v.add_argument("--skill", help="per-skill mode: verify skills/<skill> against <engagement>/<skill>")
    v.add_argument("--json", action="store_true")

    s = sub.add_parser("status", help="summarize findings + scope")
    s.add_argument("engagement")

    ap_ = sub.add_parser("approve", help="review/approve autonomous deferrals, then --resume")
    ap_.add_argument("engagement")
    ap_.add_argument("--list", action="store_true", help="just list pending deferrals")
    ap_.add_argument("--all", action="store_true", help="approve all pending")
    ap_.add_argument("--id", action="append", metavar="FP", help="approve by fingerprint (prefix ok)")

    acc = sub.add_parser("accounts",
                         help="register test-account credentials (secrets stay in runtime/creds.json — never committed or served)")
    acc.add_argument("action", choices=["add", "list", "rm", "materialize"])
    acc.add_argument("engagement", help="engagement id or path")
    acc.add_argument("--id", help="stable account id (matches notebook test_accounts[].id)")
    acc.add_argument("--role", help="e.g. user / admin / attacker / victim")
    acc.add_argument("--tenant")
    acc.add_argument("--identity",
                     help="email / ARN / API scope — stored RAW in creds.json, REDACTED in the notebook")
    acc.add_argument("--auth", metavar="METHOD",
                     help="auth method label (password / password+TOTP / API key / cookie session …)")
    acc.add_argument("--status", choices=list(accounts.STATUSES), default="active")
    acc.add_argument("--used-for", help="what this identity is for, e.g. 'IDOR victim B'")
    acc.add_argument("--password")
    acc.add_argument("--token", help="bearer token")
    acc.add_argument("--cookie", help="raw Cookie header value")
    acc.add_argument("--header", action="append", metavar="K: V", help="extra auth header (repeatable)")
    return ap


_DISPATCH = {
    "version": cmd_version,
    "doctor": cmd_doctor,
    "install": cmd_install,
    "init": cmd_init,
    "audit": cmd_audit,
    "run": cmd_run,
    "console": cmd_console,
    "verify": cmd_verify,
    "status": cmd_status,
    "approve": cmd_approve,
    "accounts": cmd_accounts,
}


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.no_color:
        ui.set_color(False)
    repo = repo_root(args.repo)

    if not args.command:
        if not args.no_banner:
            ui.print_banner(f"authorized offensive security  ·  engine: Claude Code  ·  v{__version__}")
        ap.print_help()
        return 0
    if args.command != "version" and repo is None:
        print(ui.err("could not locate the redstrike-ai repo — pass --repo <path> or set REDSTRIKE_REPO"))
        return 2
    return _DISPATCH[args.command](args, repo)


if __name__ == "__main__":
    sys.exit(main())
