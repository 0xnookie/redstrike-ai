---
name: redstrike-xss-hunter
description: Run the Redstrike XSS-only hunt — a depth-first single-class bug-bounty mission for XSS. Parse scope (XSS-pinned), XSS-scoped recon, the xss-context feeder, the four gated+reviewed variants (reflected/stored/dom/blind), escalation/chaining, triage/de-dupe, and package submission-ready reports (accepted + in-scope + non-duplicate only). Mission orchestrator (review.md only).
---

Run the Redstrike **XSS hunter** mission (canonical spec: `skills/xss-hunter/`). TIER-3 single-class mission agent — inherits `skills/_contract/hunter-base.md`. This is `bug-bounty` pinned to XSS: SAME machinery (the `xss-context` feeder + the four variants + their reviewers + packaging), narrower scope, deeper iteration.

1. **Scope + rules (strict, XSS-pinned):** read `skills/_contract/roe-gate.md` + `skills/_contract/hunter-base.md`. Parse the program's scope + rules into `program_scope.json` + `scope.yaml`; only XSS is in play. In-scope assets only; honor exclusions (no DoS / social-eng / disallowed automation); obey rate limits. **Only submit accepted, in-scope, non-duplicate findings**, and submissions are DRAFTS a human sends.
2. **Execute (orchestrate):** follow `skills/xss-hunter/SKILL.md` → XSS recon (`redstrike-js-analysis`) → `redstrike-xss-context` → the four variants `redstrike-xss-{reflected,stored,dom,blind}` (each mechanical-gated + its reviewer subagent; only `accepted` advance) → escalate per `skills/xss-context/refs/hunt_flow.md` + `redstrike-attack-chain-discovery` → triage/de-dupe → `redstrike-reporting` + per-finding drafts in `submissions/`. Write outputs to `<engagement>/xss-hunter/`.
3. **Coverage:** copy your filled checklist into `<engagement>/xss-hunter/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xss-hunter --out <engagement>/xss-hunter` → fix + re-run until exit 0.
5. Single-class mission orchestrator — **no findings of its own, no reviewer** (the XSS variant agents' reviewers verified every finding). Deliver drafts for a human to submit.
