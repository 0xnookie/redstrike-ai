---
name: redstrike-ssrf-blind
description: Run the Redstrike blind SSRF hunt (executor) — server-side fetch with no in-band reflection, confirmed by an attributable OOB callback — then gate and hand off to the ssrf-blind-verify reviewer agent.
---

Run the Redstrike **ssrf-blind** methodology (canonical spec: `skills/ssrf-blind/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; `oob.collaborator` required; benign OOB only; timing probes must not stress internal services.
2. **Execute:** follow `skills/ssrf-blind/SKILL.md`; consume `<engagement>/ssrf-context/ssrf_context.json` (blind sinks); work `skills/ssrf-blind/checklist.md`; use `skills/ssrf-context/refs/`. Write outputs to `<engagement>/ssrf-blind/`. Keep the OOB listener up — callbacks are async.
3. **Coverage:** copy your filled checklist into `<engagement>/ssrf-blind/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ssrf-blind --out <engagement>/ssrf-blind` → fix + re-run until exit 0. (Empty `callbacks.jsonl` is a valid pass.)
5. **Reviewer:** launch the `ssrf-blind-verify` subagent on `<engagement>/ssrf-blind`. A finding requires an attributable callback; only `accepted` findings go to reporting.
