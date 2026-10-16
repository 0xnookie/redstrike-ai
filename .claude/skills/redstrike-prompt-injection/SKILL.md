---
name: redstrike-prompt-injection
description: Run the Redstrike prompt-injection hunt (OWASP LLM01) — direct/indirect/role injection + output-filter bypass, proven with a benign canary — then gate and hand off to the prompt-injection-verify reviewer agent.
---

Run the Redstrike **prompt-injection** methodology (canonical spec: `skills/prompt-injection/`). OWASP LLM01.

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. BENIGN proof only — subvert the model to reveal a PLANTED canary / beacon OOB; **never** generate genuinely harmful content, real secrets, or real user data. Indirect payloads go in tester-controlled docs/RAG. Rate-limit (cost).
2. **Execute:** follow `skills/prompt-injection/SKILL.md`; consume `<engagement>/llm-context/llm_context.json` (injection points, guardrails); work `skills/prompt-injection/checklist.md`; use `skills/llm-context/refs/`. Write outputs to `<engagement>/prompt-injection/`.
3. **Coverage:** copy your filled checklist into `<engagement>/prompt-injection/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/prompt-injection --out <engagement>/prompt-injection` → fix + re-run until exit 0.
5. **Reviewer:** launch the `prompt-injection-verify` subagent on `<engagement>/prompt-injection`. Only `accepted` findings go to reporting.
