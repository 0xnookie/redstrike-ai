---
name: redstrike
description: Run a Redstrike engagement end-to-end — set up scope, run recon, route to vuln-category agents, gate each with its mechanical check + independent reviewer subagent, and assemble the report. The Redstrike entry point / orchestrator.
---

Drive a Redstrike engagement. You are the **Engagement Orchestrator** (see `skills/_contract/agent-tiers.md`).
Coordinate through artifacts on disk + the gates — never skip a gate.

## Setup
1. Create `engagements/<client>-<date>/`; copy `engagements/_template/scope.yaml` and fill it
   (authorization, in/out scope, window, RoE, `oob.collaborator`). **Nothing active runs until scope
   is set** (`skills/_contract/roe-gate.md`).

## Tier 1 — global recon
2. Run the `redstrike-js-analysis` skill into `<engagement>/js-analysis/` (add content/host discovery
   when available). Gate it (mechanical only — recon).

## Tier 2 — vuln categories  (route per `skills/_contract/vuln-catalog.md`)
3. Run the relevant `<class>-context` feeder, then its variant/category skills. XSS example:
   `redstrike-xss-context` → then `redstrike-xss-reflected | xss-stored | xss-dom | xss-blind`
   (each consumes `<engagement>/xss-context/xss_context.json`). Atomic classes (csrf, cors,
   open-redirect, …) run directly off recon.
4. After EACH findings-producing skill: run its mechanical gate
   (`verify_completion.py`), then launch its `<skill>-verify` **reviewer subagent** on the skill's
   output dir. Only `accepted` findings advance.

## Gating + progression
5. A skill is done only when: `checklist.md` is all `- [x]`, `review.md` passes (exit 0), and — for
   findings skills — every finding is `accepted` by its reviewer. Re-run failed/`needs-evidence`
   steps. `exploitation` / `post-exploitation` phases **pause for human approval** before the first
   active action.

## Report
6. Collect `accepted` findings across skills → assemble the engagement report under
   `<engagement>/report/`. (Tier-3 agents — Attack Chain Discovery, Exploit Generator, CVE
   Intelligence — plug in here once built; see `skills/_contract/agent-tiers.md`.)

Everything stays in the engagement dir — it is the audit trail and chain of custody.
