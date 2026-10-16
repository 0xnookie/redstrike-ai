---
name: redstrike-request-smuggling
description: Run the Redstrike HTTP request-smuggling hunt (executor) — HIGH-RISK desync, approval-gated, confirmed safely via self-canary — then gate and hand off to the request-smuggling-verify reviewer agent.
---

Run the Redstrike **request-smuggling** methodology (canonical spec: `skills/request-smuggling/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. HIGH blast radius — **get human approval before active confirmation**. Confirm ONLY via timing + a self-poisoning canary (your own next request); never capture real-user traffic.
2. **Execute:** follow `skills/request-smuggling/SKILL.md`; consume `skills/js-analysis/tech.md`; work `skills/request-smuggling/checklist.md`; use `skills/request-smuggling/refs/`. Write outputs to `<engagement>/request-smuggling/` (incl. `cleanup.md`). Verify no persistent desync remains; honor the kill switch.
3. **Coverage:** copy your filled checklist into `<engagement>/request-smuggling/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/request-smuggling --out <engagement>/request-smuggling` → fix + re-run until exit 0.
5. **Reviewer:** launch the `request-smuggling-verify` subagent on `<engagement>/request-smuggling`. Only `accepted` findings go to reporting.
