---
name: redstrike-injection-context
description: Run the Redstrike injection context feeder — map interpreter sinks (template / OS command / deserializer) + engine fingerprint into injection_context.json for ssti/command-injection/deserialization. Recon feeder (review.md only). Benign probes only.
---

Run the Redstrike **injection-context** feeder (canonical spec: `skills/injection-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Benign detection probes only (arithmetic / metachar reaction / marker acceptance) — NO command execution here.
2. **Execute:** follow `skills/injection-context/SKILL.md`; consume `skills/js-analysis/` params + `tech.md`; work `skills/injection-context/checklist.md`; use `skills/injection-context/refs/`. Write outputs to `<engagement>/injection-context/` — key artifact `injection_context.json` (validate against `skills/_contract/injection_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/injection-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/injection-context --out <engagement>/injection-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `injection_context.json` feeds `redstrike-ssti | command-injection | deserialization`.
