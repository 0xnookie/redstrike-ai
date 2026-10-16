---
name: redstrike-ad-kerberos
description: Run the Redstrike AD Kerberos hunt — Kerberoasting / AS-REP roasting (offline crack) / delegation abuse / ticket capability — then gate and hand off to the ad-kerberos-verify reviewer agent. High-impact, approval-gated.
---

Run the Redstrike **ad-kerberos** methodology (canonical spec: `skills/ad-kerberos/`). AD, high-impact.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Crack hashes **OFFLINE** only. **Demonstrate the vector** (weak test SPN, S4U to a test service, ticket for a test principal) — do NOT golden-ticket+persist or compromise real DA. Clean up RBCD/tickets/created objects (`cleanup.md`).
2. **Execute:** follow `skills/ad-kerberos/SKILL.md`; consume `<engagement>/ad-context/ad_context.json` (principals/flags + foothold); work `skills/ad-kerberos/checklist.md`; use `skills/ad-context/refs/`. Write outputs to `<engagement>/ad-kerberos/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ad-kerberos/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ad-kerberos --out <engagement>/ad-kerberos` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ad-kerberos-verify` subagent on `<engagement>/ad-kerberos`. Only `accepted` findings go to reporting.
