---
name: redstrike-open-redirect
description: Run the Redstrike open-redirect hunt (executor) — external redirects + chain impact — then gate and hand off to the open-redirect-verify reviewer agent.
---

Run the Redstrike **open-redirect** methodology (canonical spec: `skills/open-redirect/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; redirect payloads point off-site to YOUR benign/OOB host.
2. **Execute:** follow `skills/open-redirect/SKILL.md`; consume `skills/js-analysis/` params/endpoints; work `skills/open-redirect/checklist.md`; use `skills/open-redirect/refs/`. Write outputs to `<engagement>/open-redirect/`. Flag chains for the SSRF/XSS/auth agents.
3. **Coverage:** copy your filled checklist into `<engagement>/open-redirect/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/open-redirect --out <engagement>/open-redirect` → fix + re-run until exit 0.
5. **Reviewer:** launch the `open-redirect-verify` subagent on `<engagement>/open-redirect`. Only `accepted` findings go to reporting.
