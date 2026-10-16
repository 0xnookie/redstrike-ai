---
name: redstrike-xxe-inband
description: Run the Redstrike in-band XXE hunt (executor) — external entity resolved with content reflected (benign file read / internal fetch) — then gate and hand off to the xxe-inband-verify reviewer agent.
---

Run the Redstrike **xxe-inband** methodology (canonical spec: `skills/xxe-inband/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** (file read / SSRF); prefer `/etc/hostname` over sensitive files; **no DoS**; SSRF-via-XXE stays in scope (hand cloud-metadata to `ssrf-cloud`).
2. **Execute:** follow `skills/xxe-inband/SKILL.md`; consume `<engagement>/xxe-context/xxe_context.json` (inband sinks); work `skills/xxe-inband/checklist.md`; use `skills/xxe-context/refs/`. Write outputs to `<engagement>/xxe-inband/`.
3. **Coverage:** copy your filled checklist into `<engagement>/xxe-inband/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xxe-inband --out <engagement>/xxe-inband` → fix + re-run until exit 0.
5. **Reviewer:** launch the `xxe-inband-verify` subagent on `<engagement>/xxe-inband`. Only `accepted` findings go to reporting.
