"""White-box source-audit bootstrap: clone an authorized repository into an engagement.

`redstrike audit <repo_url>` turns a repository URL into a *source-granted* engagement:
clone the repo (shallow, read-only) into ``engagements/<id>/source/``, resolve the checked-out
commit + branch, and hand back a ``source:`` block the scaffolder writes into scope.yaml. The
presence of ``scope.source`` is the signal the orchestrator uses to run the white-box pipeline.

SECURITY — THE CLONED REPO IS UNTRUSTED DATA
--------------------------------------------
This tool audits code it does not control, so the clone is treated as hostile input:
  * only ``http`` / ``https`` / ``git`` URLs are accepted (``normalize_url``); ``file://``,
    ``ssh``, scp-style ``git@host:path`` and transport-smuggling schemes (``ext::`` …) are
    rejected, and a URL carrying embedded credentials is refused (keeps secrets out of scope.yaml);
  * the clone is SHALLOW (``--depth 1``), single-branch, no submodules, no tags, no LFS blobs;
  * NOTHING from the repo is executed — no build/install/test/hooks. Git hooks are disabled
    (``core.hooksPath`` points at a non-hook path) and the transport allowlist
    (``GIT_ALLOW_PROTOCOL``) blocks ``file``/``ext``/``ssh`` even if a redirect tried to reach them;
  * system + global git config are ignored (``GIT_CONFIG_NOSYSTEM`` / ``GIT_CONFIG_GLOBAL``) so a
    local ``insteadOf`` / credential-helper / url-rewrite cannot redirect or leak;
  * the clone is time-bounded (``timeout``) and size-bounded (``max_bytes``), and it never prompts
    for credentials (``GIT_TERMINAL_PROMPT=0``) — a private repo fails fast instead of hanging;
  * clone failures are SURFACED (raised ``CloneError`` with a redacted message), never a silent no-op.

The module is stdlib-only and shells out to the system ``git`` with an argv list (no shell), so no
value is ever interpreted by a shell.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import audit as _audit  # reuse the audit-trail secret redactor for error messages

# The URL schemes the operator may paste. ``git`` is the read-only git protocol; ``http(s)`` are
# the smart-HTTP transports. Everything else (file, ssh, ftp, ext, …) is rejected.
ALLOWED_SCHEMES = ("http", "https", "git")

# The git transports git itself is permitted to use (GIT_ALLOW_PROTOCOL). Kept in lock-step with
# ALLOWED_SCHEMES so a crafted redirect can't downgrade to a local/command transport. Tests pass a
# superset (adding ``file``) to clone a local fixture offline — production always uses this default.
DEFAULT_PROTOCOLS = ("http", "https", "git")

MAX_URL_LEN = 2048
DEFAULT_TIMEOUT = 300          # seconds — a clone that takes longer is treated as failed
DEFAULT_MAX_BYTES = 2 * 1024 ** 3  # 2 GiB working-tree cap (shallow clone is usually far smaller)


class CloneError(RuntimeError):
    """A clone (or its validation) failed. The message is already secret-redacted and user-facing."""


# --- URL validation / normalization ----------------------------------------
def normalize_url(raw: str | None) -> str:
    """Validate + normalize a pasted repository URL, or raise ``ValueError`` describing the reason.

    Accepts only an explicit ``http`` / ``https`` / ``git`` URL with a host and no embedded
    credentials. Rejects ``file://``, ``ssh``/scp-style, transport-smuggling schemes, whitespace,
    control characters and a leading ``-`` (which git would read as an option)."""
    if raw is None:
        raise ValueError("no URL given")
    s = raw.strip()
    if not s:
        raise ValueError("no URL given")
    if len(s) > MAX_URL_LEN:
        raise ValueError("URL is too long")
    if any(ch in s for ch in "\x00\n\r\t "):
        raise ValueError("URL contains whitespace or control characters")
    if s.startswith("-"):
        raise ValueError("URL must not start with '-'")
    if "://" not in s:
        # a scp-style target (git@host:path) or a bare path — both are non-http transports
        raise ValueError("URL must include an explicit scheme — use http://, https:// or git://")
    parts = urlsplit(s)
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(
            f"scheme '{scheme or '(none)'}' is not allowed — use one of {', '.join(ALLOWED_SCHEMES)}"
        )
    try:
        host = parts.hostname
    except ValueError as e:  # malformed authority
        raise ValueError(f"URL host is invalid ({e})") from None
    if not host:
        raise ValueError("URL has no host")
    if parts.username or parts.password:
        raise ValueError(
            "URL must not embed credentials (user:pass@…) — use a public repo or git's credential store"
        )
    return s


def repo_name_from_url(url: str) -> str:
    """A client/engagement slug from the repo URL's last path segment ('…/acme/widgets.git' → 'widgets')."""
    from . import engagement  # local import avoids a cycle at module load

    path = urlsplit(url).path.rstrip("/")
    last = path.rsplit("/", 1)[-1] if path else ""
    if last.endswith(".git"):
        last = last[:-4]
    slug = engagement.slugify(last) if last else ""
    if slug and slug != "client":
        return slug
    host = (urlsplit(url).hostname or "repo").split(":")[0]
    return engagement.slugify(host) or "repo"


def build_source_block(repo_url: str, local_path: str, commit: str, branch: str) -> dict:
    """The shared ``source:`` contract the scaffolder writes into scope.yaml."""
    return {
        "repo_url": repo_url,
        "local_path": local_path,     # relative to the engagement dir, e.g. 'source/'
        "commit": commit,
        "branch": branch,
    }


# --- the clone --------------------------------------------------------------
def _clone_env(allow_protocols: tuple[str, ...]) -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"                 # never block waiting for credentials
    env["GIT_ALLOW_PROTOCOL"] = ":".join(allow_protocols)  # transport allowlist (blocks ext/ssh/file…)
    env["GIT_CONFIG_NOSYSTEM"] = "1"                 # ignore /etc/gitconfig
    env["GIT_CONFIG_GLOBAL"] = os.devnull            # ignore ~/.gitconfig (insteadOf / credential rewrites)
    env["GIT_LFS_SKIP_SMUDGE"] = "1"                 # don't fetch large/untrusted LFS blobs
    env.pop("GIT_ASKPASS", None)
    env.pop("SSH_ASKPASS", None)
    return env


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
    return total


def _git_out(argv: list[str], env: dict) -> str:
    p = subprocess.run(argv, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise CloneError(_audit.redact_text((p.stderr or p.stdout or "git failed").strip())[:300])
    return (p.stdout or "").strip()


def _terminate(proc: "subprocess.Popen") -> None:
    """Best-effort stop of a running clone subprocess (terminate, then kill)."""
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    except Exception:
        pass


def clone(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    depth: int = 1,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allow_protocols: tuple[str, ...] = DEFAULT_PROTOCOLS,
) -> dict:
    """Shallow-clone ``url`` into ``dest`` (which must not already exist as a non-empty dir), with
    code execution from the repo disabled. Returns ``{'commit': <sha>, 'branch': <name>}``.

    Raises ``CloneError`` (redacted, user-facing) on any failure — a missing git, an unreachable or
    private repo, a timeout, or a tree over ``max_bytes``."""
    git = shutil.which("git")
    if not git:
        raise CloneError("git not found on PATH — install git to run a source audit")
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise CloneError(f"destination already exists and is not empty: {dest}")

    # file transport is permitted ONLY when a caller explicitly allows it (tests, offline fixtures);
    # production keeps it 'never' so a redirect can't reach the local filesystem.
    file_allow = "always" if "file" in allow_protocols else "never"
    argv = [
        git,
        "-c", f"core.hooksPath={os.devnull}",   # no repo/global hooks ever run
        "-c", f"protocol.file.allow={file_allow}",
        "clone",
        "--depth", str(int(depth)),
        "--single-branch",
        "--no-recurse-submodules",
        "--no-tags",
    ]
    if branch:
        argv += ["--branch", str(branch)]
    argv += ["--", url, str(dest)]  # '--' so a '-'-leading value is never read as an option

    env = _clone_env(allow_protocols)
    # Enforce the byte cap DURING the clone: a watcher polls the growing tree and aborts the moment
    # it exceeds max_bytes, so a clone bomb can't fill the disk before a post-hoc check would fire.
    # Output goes to a temp file (not a bounded pipe) so a chatty clone can never deadlock the poll.
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as logf:
        try:
            proc = subprocess.Popen(argv, env=env, stdout=logf, stderr=subprocess.STDOUT, text=True)
        except OSError as e:
            raise CloneError(f"could not start git: {e}") from None
        deadline = time.monotonic() + timeout
        over = False
        while True:
            try:
                proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pass
            if max_bytes and _dir_size(dest) > max_bytes:
                over = True
                break
            if time.monotonic() > deadline:
                _terminate(proc)
                raise CloneError(f"clone timed out after {timeout}s")
        if over:
            _terminate(proc)
            shutil.rmtree(dest, ignore_errors=True)
            raise CloneError(f"clone exceeded the {max_bytes}-byte cap mid-transfer — aborted (possible clone bomb)")
        logf.seek(0)
        output = logf.read()
    if proc.returncode != 0:
        msg = _audit.redact_text((output or "").strip())
        raise CloneError(f"git clone failed (exit {proc.returncode}): {msg[:500] or 'no output'}")

    if max_bytes:
        size = _dir_size(dest)   # final guard: a fast clone that landed between polls
        if size > max_bytes:
            shutil.rmtree(dest, ignore_errors=True)
            raise CloneError(
                f"cloned tree is {size} bytes, over the {max_bytes}-byte cap — refusing (possible clone bomb)"
            )

    commit = _git_out([git, "-C", str(dest), "rev-parse", "HEAD"], env)
    resolved_branch = branch or _git_out([git, "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"], env)
    if resolved_branch == "HEAD":   # detached checkout — no branch name
        resolved_branch = ""
    return {"commit": commit, "branch": resolved_branch}
