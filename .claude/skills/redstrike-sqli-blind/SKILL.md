---
name: redstrike-sqli-blind
description: Run the Redstrike blind SQLi hunt (executor) — boolean/time/OOB inferential confirmation with a minimal benign inference — then gate and hand off to the sqli-blind-verify reviewer agent.
---

Run the Redstrike **sqli-blind** methodology (canonical spec: `skills/sqli-blind/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval**; read-only inference; **no destructive/stacked payloads**; keep time payloads short (SLEEP ≤5s) and rate-limited; no PII.
2. **Execute:** follow `skills/sqli-blind/SKILL.md`; consume `<engagement>/sqli-context/sqli_context.json` (blind points); work `skills/sqli-blind/checklist.md`; use `skills/sqli-context/refs/`. Write outputs to `<engagement>/sqli-blind/`. Keep the OOB listener up if used (async).
3. **Coverage:** copy your filled checklist into `<engagement>/sqli-blind/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sqli-blind --out <engagement>/sqli-blind` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sqli-blind-verify` subagent on `<engagement>/sqli-blind`. Only `accepted` findings go to reporting.
