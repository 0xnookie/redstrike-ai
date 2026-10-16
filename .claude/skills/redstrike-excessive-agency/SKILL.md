---
name: redstrike-excessive-agency
description: Run the Redstrike excessive-agency hunt (OWASP LLM06) — abuse the LLM's tools (param injection, SSRF via tools, tool chaining) to drive a benign unauthorized action — then gate and hand off to the excessive-agency-verify reviewer agent.
---

Run the Redstrike **excessive-agency** methodology (canonical spec: `skills/excessive-agency/`). OWASP LLM06.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. The LLM performs REAL actions via tools — **get approval** + kill switch; confirm with BENIGN effects only (OOB callback / no-op marker action); **never** destructive (no real emails/payments/data changes). SSRF via tools stays in scope (metadata → `ssrf-cloud`).
2. **Execute:** follow `skills/excessive-agency/SKILL.md`; consume `<engagement>/llm-context/llm_context.json` (`tools`); work `skills/excessive-agency/checklist.md`; use `skills/llm-context/refs/`. Write outputs to `<engagement>/excessive-agency/`. Downstream tool-arg injection → hand to `ssrf-*`/`sqli-*`/`command-injection`.
3. **Coverage:** copy your filled checklist into `<engagement>/excessive-agency/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/excessive-agency --out <engagement>/excessive-agency` → fix + re-run until exit 0.
5. **Reviewer:** launch the `excessive-agency-verify` subagent on `<engagement>/excessive-agency`. Only `accepted` findings go to reporting.
