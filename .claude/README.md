# Redstrike — Claude Code runtime binding

This `.claude/` dir is the **Claude Code binding** over the portable framework in [`../skills/`](../skills/).
The framework content (methodologies, checklists, reviewer gauntlets, schemas, the verifier) is
substrate-agnostic; this dir wires it into Claude Code's two runtime primitives.

| Framework file | Becomes a… | Lives here as |
|---|---|---|
| `skills/<name>/SKILL.md` (+ checklist, refs) | **Skill** — instructions an executor follows (shares its context) | `.claude/skills/redstrike-<name>/SKILL.md` (thin binding) |
| `skills/<name>/verify.md` | **Subagent** — an independent reviewer with its OWN context | `.claude/agents/<name>-verify.md` |
| `skills/<name>/review.md` + `verify_completion.py` | **Script gate** — deterministic, no model | run via `Bash` / a hook |

## Skill vs. agent (why it matters here)
- A **Skill** is instructions loaded into the current context.
- A **Subagent (agent)** is an independent runner with its **own context window**.
- The reviewer is an **agent, not a skill, on purpose**: independence is the whole point — an
  executor cannot trustworthily grade its own work (it shares its own blind spots). The reviewer runs
  fresh, sees only the findings + evidence, and is adversarial.

## Entry point
Invoke the **`redstrike`** skill (orchestrator): it runs recon → vuln-category skills → each skill's
reviewer subagent, gated, and assembles the report.

## Registered here
- **Reviewer subagents** (`.claude/agents/`): `xss-reflected-verify`, `xss-stored-verify`,
  `xss-dom-verify`, `xss-blind-verify`, `csrf-verify`, `cors-verify`, `open-redirect-verify`.
- **Skill bindings** (`.claude/skills/`): `redstrike` (orchestrator) + `redstrike-<skill>` for each
  built skill (js-analysis, xss-context, xss-reflected/stored/dom/blind, csrf, cors, open-redirect).

## Discovery
Claude Code loads `.claude/skills/` and `.claude/agents/` **at session start**, so new entries here
take effect in a **new session** (and for teammates via git) — not necessarily mid-session.

## Agent SDK alternative
The same mapping holds without Claude Code: `SKILL.md` → a Skill, `verify.md` → a subagent,
`review.md` → a hook that shells out to `verify_completion.py`. See `../skills/_contract/README.md`.
