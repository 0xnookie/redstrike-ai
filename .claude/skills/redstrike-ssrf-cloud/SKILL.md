---
name: redstrike-ssrf-cloud
description: Run the Redstrike cloud-metadata SSRF hunt (executor) — reach the cloud metadata service via a sink and retrieve instance creds (redacted) — then gate and hand off to the ssrf-cloud-verify reviewer agent.
---

Run the Redstrike **ssrf-cloud** methodology (canonical spec: `skills/ssrf-cloud/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Metadata creds = direct cloud compromise — **get approval**; retrieve creds only to PROVE access, store REDACTED, **never use them** to touch cloud resources.
2. **Execute:** follow `skills/ssrf-cloud/SKILL.md`; consume `<engagement>/ssrf-context/ssrf_context.json` (cloud sinks) + `skills/js-analysis/tech.md` (provider); work `skills/ssrf-cloud/checklist.md`; use `skills/ssrf-cloud/refs/metadata_endpoints.md`. Write outputs to `<engagement>/ssrf-cloud/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ssrf-cloud/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ssrf-cloud --out <engagement>/ssrf-cloud` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ssrf-cloud-verify` subagent on `<engagement>/ssrf-cloud`. Only `accepted` findings go to reporting.
