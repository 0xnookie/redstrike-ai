---
name: redstrike-security-headers
description: Run the Redstrike security-headers assessment (executor) — report only header gaps with a concrete contextual attack path, honestly rated — then gate and hand off to the security-headers-verify reviewer agent.
---

Run the Redstrike **security-headers** methodology (canonical spec: `skills/security-headers/`).

1. **Scope:** read the engagement `scope.yaml` (read-only skill). The risk here is REPORT quality, not blast radius.
2. **Execute:** follow `skills/security-headers/SKILL.md`; consume `skills/js-analysis/` key pages; work `skills/security-headers/checklist.md`. Write outputs to `<engagement>/security-headers/`. Cross-reference `clickjacking` (XFO), `cors` (ACAO), `xss-*` (CSP) — don't double-report their bugs; report the header POSTURE with honest severity.
3. **Coverage:** copy your filled checklist into `<engagement>/security-headers/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/security-headers --out <engagement>/security-headers` → fix + re-run until exit 0.
5. **Reviewer:** launch the `security-headers-verify` subagent on `<engagement>/security-headers`. Only `accepted` findings go to reporting (it will down-rate best-practice noise).
