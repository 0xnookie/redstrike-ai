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

from . import __version__, engagement, gate, launch, preflight, ui
from . import scope as scopemod


def repo_root(override: str | None = None) -> Path:
    if override:
        return Path(override).resolve()
    env = os.environ.get("REDSTRIKE_REPO")
    if env:
        return Path(env).resolve()
    # cli/redstrike_cli/__main__.py -> repo root is two levels up from the package dir.
    return Path(__file__).resolve().parents[2]


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
    print(ui.kv("repo", str(repo)))
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
        ui.print_banner(f"engagement {eng_dir.name}")

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

    r = sub.add_parser("run", help="launch the engagement (interactive, gated)")
    r.add_argument("engagement", help="engagement id or path")
    r.add_argument("--dry-run", action="store_true", help="prepare + print the argv; do not launch")
    r.add_argument("--permission-mode", default="default", choices=["default", "plan", "acceptEdits"])
    r.add_argument("--prompt", help="override the initial prompt")

    v = sub.add_parser("verify", help="run the mechanical gate (verify_completion.py)")
    v.add_argument("engagement")
    v.add_argument("--skill", help="per-skill mode: verify skills/<skill> against <engagement>/<skill>")
    v.add_argument("--json", action="store_true")

    s = sub.add_parser("status", help="summarize findings + scope")
    s.add_argument("engagement")
    return ap


_DISPATCH = {
    "version": cmd_version,
    "doctor": cmd_doctor,
    "init": cmd_init,
    "run": cmd_run,
    "verify": cmd_verify,
    "status": cmd_status,
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
    return _DISPATCH[args.command](args, repo)


if __name__ == "__main__":
    sys.exit(main())
