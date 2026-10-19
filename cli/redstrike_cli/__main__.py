"""`redstrike` — launch Claude Code as a scoped, gated pentest engine.

Subcommands: doctor | init | run | verify | status | version.
v1 is interactive and human-gated; autonomous headless (-p) is a later milestone.
"""
from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

from . import __version__, autorun, engagement, gate, launch, preflight, ui
from . import approvals as approvalsmod
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
    if not args.no_banner:
        ui.print_banner("preflight — engine, auth, platform, tools")
    print(ui.rule("launcher preflight"))
    checks = preflight.gather(repo)
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


def cmd_run(args, repo: Path) -> int:
    eng_dir = resolve_engagement(repo, args.engagement)
    if not eng_dir:
        print(ui.err(f"engagement '{args.engagement}' not found under {repo / 'engagements'}"))
        return 1
    if not args.no_banner:
        ui.print_banner(f"engagement {eng_dir.name}" + ("  ·  AUTONOMOUS" if args.autonomous else ""))

    if args.autonomous:
        return _run_autonomous(args, repo, eng_dir)

    try:
        prep = launch.prepare_runtime(eng_dir, repo, sys.executable)
    except FileNotFoundError as e:
        print(ui.err(str(e)))
        return 1

    for line in scopemod.summary_lines(prep.scope):
        print(f"  {line}")

    problems = launch.gate(prep)
    if problems:
        print()
        for p in problems:
            print(ui.err(p))
        print(ui.err("launch blocked (fail-closed). Fix scope.yaml / window and re-run."))
        return 2

    claude_bin = preflight.find_claude()
    prompt = args.prompt or launch.default_prompt(prep.engagement_id)
    argv = launch.build_argv(claude_bin or "claude", repo, prep, prompt, args.permission_mode)

    if args.dry_run or not claude_bin:
        print()
        print(ui.rule("DRY RUN — generated runtime artifacts"))
        print(ui.kv("scope.json", str(prep.scope_json.relative_to(repo))))
        print(ui.kv("settings", str(prep.settings_path.relative_to(repo))))
        print(ui.kv("roe", str(prep.roe_path.relative_to(repo))))
        print(ui.kv("session", prep.session_id))
        print()
        print(ui.rule("would exec"))
        print("  " + " ".join(shlex.quote(a) for a in argv))
        if not claude_bin and not args.dry_run:
            print()
            print(ui.err("`claude` not on PATH — printed the plan instead of launching."))
            return 127
        return 0

    authed, detail = preflight.claude_auth(claude_bin)
    if authed is False:
        print(ui.err(f"claude not authenticated: {detail}"))
        return 1
    print()
    print(ui.ok("scope gate armed · launching Claude Code engine (interactive, gated)…"))
    print()
    return launch.exec_claude(argv, cwd=eng_dir)


def _run_autonomous(args, repo: Path, eng_dir: Path) -> int:
    extra_allow = args.allow or []
    try:
        prep = launch.prepare_runtime(
            eng_dir, repo, sys.executable, mode="autonomous", extra_allow=extra_allow
        )
    except FileNotFoundError as e:
        print(ui.err(str(e)))
        return 1

    for line in scopemod.summary_lines(prep.scope):
        print(f"  {line}")
    problems = launch.gate(prep)
    if problems:
        print()
        for p in problems:
            print(ui.err(p))
        print(ui.err("launch blocked (fail-closed). Fix scope.yaml / window and re-run."))
        return 2

    claude_bin = preflight.find_claude()
    allowed = settingsmod.autonomous_allowlist(extra_allow)
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
    argv = launch.build_autonomous_argv(
        claude_bin or "claude", repo, prep, prompt, allowed,
        max_turns=args.max_turns, max_budget=args.max_budget_usd, resume=args.resume,
    )

    if args.dry_run or not claude_bin:
        print()
        print(ui.rule("DRY RUN — autonomous argv"))
        print(ui.kv("allowlist", " ".join(allowed)))
        print(ui.kv("caps", f"max_turns={args.max_turns}  budget=${args.max_budget_usd}"))
        print("  " + " ".join(shlex.quote(a) for a in argv))
        if not claude_bin and not args.dry_run:
            print(ui.err("`claude` not on PATH — printed the plan instead of launching."))
            return 127
        return 0

    authed, detail = preflight.claude_auth(claude_bin)
    if authed is False:
        print(ui.err(f"claude not authenticated: {detail}"))
        return 1
    print()
    print(ui.ok(f"scope gate armed · autonomous headless run (dontAsk, max_turns={args.max_turns}, budget=${args.max_budget_usd})…"))
    print()
    audit = eng_dir / "runtime" / "autorun.jsonl"
    rc, _summary = autorun.run_autonomous(claude_bin, argv, eng_dir, audit, pending_path=prep.pending_path)
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


# --- parser ----------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="redstrike", description="Run Claude Code as a scoped pentest engine.")
    ap.add_argument("--repo", help="path to the redstrike-ai repo (default: autodetect / $REDSTRIKE_REPO)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--no-banner", action="store_true", help="suppress the REDSTRIKE banner")
    sub = ap.add_subparsers(dest="command")

    sub.add_parser("version", help="show versions")

    d = sub.add_parser("doctor", help="preflight: engine, auth, platform, tool roster")
    d.add_argument("--env", action="store_true", help="only the runtime-environment preflight")
    d.add_argument("--core", action="store_true", help="core tool categories only")
    d.add_argument("--all", action="store_true", dest="all_cats", help="all tool categories")
    d.add_argument("--missing", action="store_true", help="list only missing tools")
    d.add_argument("categories", nargs="*", help="specific tool categories (e.g. web recon ad)")

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
    return ap


_DISPATCH = {
    "version": cmd_version,
    "doctor": cmd_doctor,
    "init": cmd_init,
    "run": cmd_run,
    "verify": cmd_verify,
    "status": cmd_status,
    "approve": cmd_approve,
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
