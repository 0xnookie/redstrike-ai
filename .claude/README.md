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
- **Reviewer subagents** (`.claude/agents/`): one **`<name>-verify`** per findings-producing skill —
  **80** in total (e.g. `xss-reflected-verify`, `sqli-inband-verify`, `ssrf-blind-verify`, `idor-verify`,
  `jwt-verify`, `sc-reentrancy-verify`, `ad-kerberos-verify`, `cloud-verify`, `fuzzing-verify`, …). Each
  runs with its **own fresh context**.
- **Skill bindings** (`.claude/skills/`): the **`redstrike`** orchestrator + a **`redstrike-<name>`**
  binding per skill — **105** in total (recon feeders, the vuln executors, and the AI/LLM · Web3 · AD ·
  cloud/container · mobile/IoT/wireless · binary domains, plus the Tier-3 mission/capability agents).

> These lists track `../skills/` one-to-one; rather than enumerate every entry here (and re-drift), see
> the authoritative catalog in [`../skills/_contract/vuln-catalog.md`](../skills/_contract/vuln-catalog.md)
> and the tier map in [`../skills/_contract/agent-tiers.md`](../skills/_contract/agent-tiers.md).

## Discovery
Claude Code loads `.claude/skills/` and `.claude/agents/` **at session start**, so new entries here
take effect in a **new session** (and for teammates via git) — not necessarily mid-session.

## Agent SDK alternative
The same mapping holds without Claude Code: `SKILL.md` → a Skill, `verify.md` → a subagent,
`review.md` → a hook that shells out to `verify_completion.py`. See `../skills/_contract/README.md`.
