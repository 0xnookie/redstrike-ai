---
name: redstrike-subdomain-takeover
description: Run the Redstrike subdomain-takeover hunt (executor) — dangling DNS to a claimable resource — then gate and hand off to the subdomain-takeover-verify reviewer agent.
---

Run the Redstrike **subdomain-takeover** methodology (canonical spec: `skills/subdomain-takeover/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Detection is read-only; **actually claiming** a resource needs explicit written authorization — otherwise document claimability and stop.
2. **Execute:** follow `skills/subdomain-takeover/SKILL.md`; consume the subdomain list (host-discovery / `js-analysis`); work `skills/subdomain-takeover/checklist.md`; use `skills/subdomain-takeover/refs/`. Write outputs to `<engagement>/subdomain-takeover/`.
3. **Coverage:** copy your filled checklist into `<engagement>/subdomain-takeover/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/subdomain-takeover --out <engagement>/subdomain-takeover` → fix + re-run until exit 0.
5. **Reviewer:** launch the `subdomain-takeover-verify` subagent on `<engagement>/subdomain-takeover`. Only `accepted` findings go to reporting.
