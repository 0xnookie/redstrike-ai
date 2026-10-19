"""Redstrike CLI — a thin launcher that runs Claude Code as the engagement engine.

The user runs `redstrike` instead of `claude`; the launcher bootstraps an engagement
(authorization + scope), enforces a scope/RoE gate, and starts Claude Code preloaded
with the repo's `.claude/` skills + subagents. Interactive, human-gated by default.

Stdlib-only. See cli/README.md and cli/PLAN.md.
"""

__version__ = "0.1.0"

# Minimum Claude Code CLI version the launcher relies on (flags: --add-dir,
# --append-system-prompt-file, --settings, --setting-sources, --session-id).
MIN_CLAUDE_VERSION = (2, 1, 259)
