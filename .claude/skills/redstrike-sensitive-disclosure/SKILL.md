---
name: redstrike-sensitive-disclosure
description: Run the Redstrike sensitive-disclosure hunt (OWASP LLM02/07/08) — system-prompt leakage, cross-tenant leakage, RAG/embedding extraction, corroborated (not hallucinated) — then gate and hand off to the sensitive-disclosure-verify reviewer agent.
---

Run the Redstrike **sensitive-disclosure** methodology (canonical spec: `skills/sensitive-disclosure/`). OWASP LLM02/07/08.

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Corroborate extractions (LLMs happily hallucinate plausible system prompts) — only report what's verifiably real. Cross-tenant uses tester second accounts + a planted marked record; **never** exfiltrate real users' data. Rate-limit.
2. **Execute:** follow `skills/sensitive-disclosure/SKILL.md`; consume `<engagement>/llm-context/llm_context.json` (`data_sources`); work `skills/sensitive-disclosure/checklist.md`; use `skills/llm-context/refs/`. Write outputs to `<engagement>/sensitive-disclosure/`.
3. **Coverage:** copy your filled checklist into `<engagement>/sensitive-disclosure/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sensitive-disclosure --out <engagement>/sensitive-disclosure` → fix + re-run until exit 0.
5. **Reviewer:** launch the `sensitive-disclosure-verify` subagent on `<engagement>/sensitive-disclosure`. Only `accepted` findings go to reporting.
