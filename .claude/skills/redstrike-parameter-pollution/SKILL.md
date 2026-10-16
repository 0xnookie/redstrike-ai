---
name: redstrike-parameter-pollution
description: Run the Redstrike HTTP Parameter Pollution hunt (executor) — duplicate/polluted parameters across URL/body/JSON/cookie/header exploiting gateway-vs-backend parser precedence to flip a security decision — then gate and hand off to the parameter-pollution-verify reviewer agent.
---

Run the Redstrike **parameter-pollution** methodology (canonical spec: `skills/parameter-pollution/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; use test identities; no real-account authz/value change without approval. If HPP smuggles another payload (SQLi/SSRF/XSS/smuggling), hand the vector to that agent and use its benign-proof rules.
2. **Execute:** follow `skills/parameter-pollution/SKILL.md`; consume `skills/js-analysis/` params + `content-discovery` + `tech.md` (parser behaviour); work `skills/parameter-pollution/checklist.md`; use `skills/parameter-pollution/refs/`. Write outputs to `<engagement>/parameter-pollution/`.
3. **Coverage:** copy your filled checklist into `<engagement>/parameter-pollution/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/parameter-pollution --out <engagement>/parameter-pollution` → fix + re-run until exit 0.
5. **Reviewer:** launch the `parameter-pollution-verify` subagent on `<engagement>/parameter-pollution`. Only `accepted` findings go to reporting.
