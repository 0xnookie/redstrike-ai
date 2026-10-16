---
name: redstrike-clickjacking
description: Run the Redstrike clickjacking hunt (executor) — frameable pages with a sensitive action + UI-redress PoC — then gate and hand off to the clickjacking-verify reviewer agent.
---

Run the Redstrike **clickjacking** methodology (canonical spec: `skills/clickjacking/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; don't actually perform the state change (test account, demonstrate framing + click reachability only).
2. **Execute:** follow `skills/clickjacking/SKILL.md`; consume `skills/js-analysis/` sensitive actions; work `skills/clickjacking/checklist.md`; use `skills/clickjacking/refs/`. Write outputs to `<engagement>/clickjacking/`.
3. **Coverage:** copy your filled checklist into `<engagement>/clickjacking/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/clickjacking --out <engagement>/clickjacking` → fix + re-run until exit 0.
5. **Reviewer:** launch the `clickjacking-verify` subagent on `<engagement>/clickjacking`. Only `accepted` findings go to reporting.
