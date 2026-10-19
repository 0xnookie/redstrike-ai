"""Terminal branding + output helpers for the Redstrike CLI.

Zero-dependency: ANSI colour is used only on a real TTY and when NO_COLOR is unset,
so output degrades cleanly in pipes, CI and `-p`/headless contexts. The REDSTRIKE
wordmark is an embedded FIGlet "ANSI Shadow" block (no pyfiglet needed).
"""
from __future__ import annotations

import os
import sys

# --- ANSI palette ---------------------------------------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BRIGHT_RED = "\033[91m"

# REDSTRIKE, FIGlet "ANSI Shadow" — 68 columns wide, 6 rows.
_WORDMARK = [
    "██████╗ ███████╗██████╗ ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗",
    "██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝",
    "██████╔╝█████╗  ██║  ██║███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  ",
    "██╔══██╗██╔══╝  ██║  ██║╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  ",
    "██║  ██║███████╗██████╔╝███████║   ██║   ██║  ██║██║██║  ██╗███████╗",
    "╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝",
]

_FORCE: bool | None = None  # set by set_color()


def set_color(force: bool | None) -> None:
    """Override colour autodetection: True=always, False=never, None=auto."""
    global _FORCE
    _FORCE = force


def color_enabled(stream=None) -> bool:
    if _FORCE is not None:
        return _FORCE
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def unicode_ok(stream=None) -> bool:
    """Can this stream encode the box-art/glyphs? (False on a legacy cp1252 console.)"""
    if os.environ.get("REDSTRIKE_ASCII"):
        return False
    stream = stream or sys.stdout
    enc = getattr(stream, "encoding", None)
    if not enc:  # e.g. StringIO holds str
        return True
    try:
        "✓█─•⚠✗".encode(enc)
        return True
    except Exception:
        return False


def style(text: str, *codes: str, stream=None) -> str:
    if not codes or not color_enabled(stream):
        return text
    return "".join(codes) + text + RESET


def banner(subtitle: str | None = None, *, indent: str = "  ", stream=None) -> str:
    """Render the REDSTRIKE wordmark (+ optional subtitle) as a string."""
    on = color_enabled(stream)
    if unicode_ok(stream):
        rows = [(indent + ln).rstrip() for ln in _WORDMARK]
    else:
        rows = [indent + "######  R E D S T R I K E  ######"]
    out = [(BOLD + BRIGHT_RED + r + RESET) if on else r for r in rows]
    if subtitle:
        sub = indent + subtitle
        out.append((DIM + sub + RESET) if on else sub)
    return "\n".join(out)


def rule(label: str | None = None, width: int = 66, stream=None) -> str:
    dash = "─" if unicode_ok(stream) else "-"
    if not label:
        line = dash * width
    else:
        line = f"{dash * 2} {label} " + dash * max(0, width - len(label) - 4)
    return style(line, DIM, stream=stream)


def kv(key: str, value: str, *, key_width: int = 12, stream=None) -> str:
    k = style(f"{key:<{key_width}}", DIM, stream=stream)
    return f"  {k}{value}"


def _glyph(uni: str, ascii_: str, stream) -> str:
    return uni if unicode_ok(stream) else ascii_


def ok(msg: str, stream=None) -> str:
    return f"  {style(_glyph('✓', '[ok]', stream), GREEN, stream=stream)} {msg}"


def warn(msg: str, stream=None) -> str:
    return f"  {style(_glyph('⚠', '[!]', stream), YELLOW, stream=stream)} {msg}"


def err(msg: str, stream=None) -> str:
    return f"  {style(_glyph('✗', '[x]', stream), RED, stream=stream)} {msg}"


def info(msg: str, stream=None) -> str:
    return f"  {style(_glyph('•', '[-]', stream), CYAN, stream=stream)} {msg}"


def print_banner(subtitle: str | None = None, *, stream=None) -> None:
    stream = stream or sys.stdout
    print(banner(subtitle, stream=stream), file=stream)
    print(file=stream)
