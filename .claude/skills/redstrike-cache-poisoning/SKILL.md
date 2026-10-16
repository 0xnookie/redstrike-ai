---
name: redstrike-cache-poisoning
description: Run the Redstrike web-cache-poisoning hunt (executor) — unkeyed input into a shared cache, confirmed by a cross-user hit, buster-scoped — then gate and hand off to the cache-poisoning-verify reviewer agent.
---

Run the Redstrike **cache-poisoning** methodology (canonical spec: `skills/cache-poisoning/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Poisoning a shared cache hits real users — **scope the poison to a unique cache-buster you control**, keep payloads benign, and get **approval** before poisoning a production cache key.
2. **Execute:** follow `skills/cache-poisoning/SKILL.md`; consume `skills/js-analysis/`; work `skills/cache-poisoning/checklist.md`; use `skills/cache-poisoning/refs/`. Write outputs to `<engagement>/cache-poisoning/` (incl. `cleanup.md`); purge / let short TTL expire.
3. **Coverage:** copy your filled checklist into `<engagement>/cache-poisoning/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/cache-poisoning --out <engagement>/cache-poisoning` → fix + re-run until exit 0.
5. **Reviewer:** launch the `cache-poisoning-verify` subagent on `<engagement>/cache-poisoning`. Only `accepted` findings go to reporting.
