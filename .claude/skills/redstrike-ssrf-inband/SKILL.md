---
name: redstrike-ssrf-inband
description: Run the Redstrike in-band SSRF hunt (executor) — server fetches an attacker-chosen internal target with the response observable — then gate and hand off to the ssrf-inband-verify reviewer agent.
---

Run the Redstrike **ssrf-inband** methodology (canonical spec: `skills/ssrf-inband/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Reaching internal resources is sensitive — **get approval**; stay within in-scope internal ranges; read-only.
2. **Execute:** follow `skills/ssrf-inband/SKILL.md`; consume `<engagement>/ssrf-context/ssrf_context.json` (inband sinks + internal_targets); work `skills/ssrf-inband/checklist.md`; use `skills/ssrf-context/refs/`. Write outputs to `<engagement>/ssrf-inband/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ssrf-inband/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ssrf-inband --out <engagement>/ssrf-inband` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ssrf-inband-verify` subagent on `<engagement>/ssrf-inband`. Only `accepted` findings go to reporting.
