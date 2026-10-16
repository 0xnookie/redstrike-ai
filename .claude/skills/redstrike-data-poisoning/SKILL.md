---
name: redstrike-data-poisoning
description: Run the Redstrike data-poisoning hunt (executor, OWASP LLM04 / MITRE ATLAS) — training / fine-tune / RAG-embedding / ingestion-pipeline poisoning, confirmed benignly in a TEST corpus with a trigger→marker association or a crafted doc that out-ranks the legit doc — then gate and hand off to the data-poisoning-verify reviewer agent. Approval-gated.
---

Run the Redstrike **data-poisoning** methodology (canonical spec: `skills/data-poisoning/`). OWASP LLM04.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (writing a corpus/index/training set); operate ONLY on an authorized TEST corpus/index/training run; BENIGN proof only — a trigger→marker association or a #1-ranking TEST doc; never poison a production model or live shared index or use real user data. Label + remove every injected artifact afterward.
2. **Execute:** follow `skills/data-poisoning/SKILL.md`; consume the data pipeline (training/fine-tune/RAG index/ingestion sources) from `<engagement>/llm-context/llm_context.json`; work `skills/data-poisoning/checklist.md`; use `skills/data-poisoning/refs/`. Write outputs to `<engagement>/data-poisoning/`.
3. **Coverage:** copy your filled checklist into `<engagement>/data-poisoning/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/data-poisoning --out <engagement>/data-poisoning` → fix + re-run until exit 0.
5. **Reviewer:** launch the `data-poisoning-verify` subagent on `<engagement>/data-poisoning`. Only `accepted` findings go to reporting.
