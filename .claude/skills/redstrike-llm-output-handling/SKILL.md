---
name: redstrike-llm-output-handling
description: Run the Redstrike LLM output-handling hunt (OWASP LLM05) — make the model emit a payload that executes at a downstream sink (XSS/SQLi/SSRF/RCE) — then gate and hand off to the llm-output-handling-verify reviewer agent.
---

Run the Redstrike **llm-output-handling** methodology (canonical spec: `skills/llm-output-handling/`). OWASP LLM05.

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Benign downstream payloads (print/OOB/markers — same rules as the web agents); the LLM is just the delivery vector, the downstream agent's safety rules apply. Rate-limit.
2. **Execute:** follow `skills/llm-output-handling/SKILL.md`; consume `<engagement>/llm-context/llm_context.json` (`output_sinks`); work `skills/llm-output-handling/checklist.md`; use `skills/llm-context/refs/`. Write outputs to `<engagement>/llm-output-handling/`. Confirm the downstream sink via `redstrike-xss-*`/`sqli-*`/`ssrf-*`/`command-injection`.
3. **Coverage:** copy your filled checklist into `<engagement>/llm-output-handling/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/llm-output-handling --out <engagement>/llm-output-handling` → fix + re-run until exit 0.
5. **Reviewer:** launch the `llm-output-handling-verify` subagent on `<engagement>/llm-output-handling`. Only `accepted` findings go to reporting.
