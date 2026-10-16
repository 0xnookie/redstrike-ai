---
name: redstrike-nosql-injection
description: Run the Redstrike NoSQL injection hunt (executor) — operator/syntax injection into NoSQL query languages (MongoDB, …) for auth bypass or query manipulation, confirmed benignly — then gate and hand off to the nosql-injection-verify reviewer agent.
---

Run the Redstrike **nosql-injection** methodology (canonical spec: `skills/nosql-injection/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; approval required (data access); use a test account; benign + minimal — no bulk extraction, no DB-hanging `$where`.
2. **Execute:** follow `skills/nosql-injection/SKILL.md`; consume `skills/js-analysis/` params + `content-discovery` + `tech.md` (NoSQL fingerprint); work `skills/nosql-injection/checklist.md`; use `skills/nosql-injection/refs/`. Write outputs to `<engagement>/nosql-injection/`.
3. **Coverage:** copy your filled checklist into `<engagement>/nosql-injection/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/nosql-injection --out <engagement>/nosql-injection` → fix + re-run until exit 0.
5. **Reviewer:** launch the `nosql-injection-verify` subagent on `<engagement>/nosql-injection`. Only `accepted` findings go to reporting.
