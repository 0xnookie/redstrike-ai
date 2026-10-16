---
name: redstrike-xss-dom
description: Run the Redstrike DOM-XSS hunt (executor) — client-side source->sink taint that executes — then gate and hand off to the xss-dom-verify reviewer agent.
---

Run the Redstrike **xss-dom** methodology (canonical spec: `skills/xss-dom/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; scope-gate page loads (lowest blast radius — fragment sources never reach the server).
2. **Execute:** follow `skills/xss-dom/SKILL.md`; consume `<engagement>/xss-context/xss_context.json` (`dom.*`) + `skills/js-analysis/` beautified JS; work `skills/xss-dom/checklist.md`; use `skills/xss-dom/refs/`. Write outputs to `<engagement>/xss-dom/` (PoCs are `poc_urls.txt` + `poc/`, not curl).
3. **Coverage:** copy your filled checklist into `<engagement>/xss-dom/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xss-dom --out <engagement>/xss-dom` → fix + re-run until exit 0.
5. **Reviewer:** launch the `xss-dom-verify` subagent on `<engagement>/xss-dom`. Only `accepted` findings go to reporting.
