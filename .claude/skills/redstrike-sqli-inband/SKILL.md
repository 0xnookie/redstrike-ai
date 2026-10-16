---
name: redstrike-sqli-inband
description: Run the Redstrike in-band SQLi hunt (executor) — error/union data extraction with a minimal read-only proof — then gate and hand off to the sqli-inband-verify reviewer agent.
---

Run the Redstrike **sqli-inband** methodology (canonical spec: `skills/sqli-inband/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** (data access); read-only, SELECT-safe; **no destructive queries**; extract only a minimal benign proof (version/db name/one row) — never dump real PII.
2. **Execute:** follow `skills/sqli-inband/SKILL.md`; consume `<engagement>/sqli-context/sqli_context.json` (inband points); work `skills/sqli-inband/checklist.md`; use `skills/sqli-context/refs/`. Write outputs to `<engagement>/sqli-inband/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sqli-inband/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sqli-inband --out <engagement>/sqli-inband` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sqli-inband-verify` subagent on `<engagement>/sqli-inband`. Only `accepted` findings go to reporting.
