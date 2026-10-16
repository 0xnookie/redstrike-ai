---
name: redstrike-bug-bounty
description: Run the Redstrike bug-bounty mission — parse program scope/rules, recon, prioritized gated hunt, chaining, triage/de-dupe, and package submission-ready reports (accepted + in-scope + non-duplicate only). Mission orchestrator (review.md only).
---

Run the Redstrike **bug-bounty** mission (canonical spec: `skills/bug-bounty/`). TIER-3 mission agent.

1. **Scope + rules (strict):** read `skills/_contract/roe-gate.md`. Parse the program's scope + rules into `program_scope.json` + `scope.yaml`. Bug-bounty programs are STRICTER than pentests — in-scope assets only; honor exclusions (no DoS / social-eng / disallowed automation); obey rate limits. **Only submit accepted, in-scope, non-duplicate findings**, and submissions are DRAFTS a human sends.
2. **Execute (orchestrate):** follow `skills/bug-bounty/SKILL.md` → recon (`redstrike-js-analysis`) → prioritize (`redstrike-cve-intelligence`) → run the applicable `redstrike-<vuln>` skills (each mechanical-gated + its reviewer subagent; only `accepted` advance) → `redstrike-attack-chain-discovery` → triage/de-dupe → `redstrike-reporting` + per-finding drafts in `submissions/`. Write outputs to `<engagement>/bug-bounty/`.
3. **Coverage:** copy your filled checklist into `<engagement>/bug-bounty/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/bug-bounty --out <engagement>/bug-bounty` → fix + re-run until exit 0.
5. Mission orchestrator — **no findings of its own, no reviewer** (the vuln agents' reviewers verified every finding). Deliver drafts for a human to submit.
