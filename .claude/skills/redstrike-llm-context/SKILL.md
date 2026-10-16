---
name: redstrike-llm-context
description: Run the Redstrike LLM context feeder — map an LLM app's surface (model, chat API, guardrails, tools/agency, data sources, output sinks) into llm_context.json for the OWASP-LLM-Top-10 variant agents. Recon feeder (review.md only). Benign probes.
---

Run the Redstrike **llm-context** feeder (canonical spec: `skills/llm-context/`). TIER-2 (AI/LLM).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Benign probes only (model ID, guardrail classification) — no jailbreaks/harmful content here. Treat model output as UNTRUSTED; rate-limit (LLM calls cost).
2. **Execute:** follow `skills/llm-context/SKILL.md`; consume `skills/js-analysis/` + `content-discovery` endpoints; work `skills/llm-context/checklist.md`; use `skills/llm-context/refs/llm_testing_guide.md`. Write outputs to `<engagement>/llm-context/` — key artifact `llm_context.json` (validate against `skills/_contract/llm_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/llm-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/llm-context --out <engagement>/llm-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `llm_context.json` feeds `redstrike-prompt-injection | sensitive-disclosure | excessive-agency | llm-output-handling`.
