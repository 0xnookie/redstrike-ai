---
name: redstrike-fuzzing
description: Run the Redstrike fuzzing hunt (executor) — coverage-guided + structure-aware + network/API fuzzing of an authorized target to surface reproducible memory-safety crashes, triaged + deduped + minimized to a sanitizer-traced PoC input — then gate and hand off to the fuzzing-verify reviewer agent. Approval-gated.
---

Run the Redstrike **fuzzing** methodology (canonical spec: `skills/fuzzing/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (fuzzing can crash services); fuzz an authorized/dedicated instance only, never shared production; rate-limit network/API campaigns; in-scope target only.
2. **Execute:** follow `skills/fuzzing/SKILL.md`; build an instrumented harness + seed corpus, run the campaign, then triage + dedup + minimize; work `skills/fuzzing/checklist.md`; use `skills/fuzzing/refs/`. Write outputs to `<engagement>/fuzzing/`.
3. **Coverage:** copy your filled checklist into `<engagement>/fuzzing/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/fuzzing --out <engagement>/fuzzing` → fix + re-run until exit 0.
5. **Reviewer:** launch the `fuzzing-verify` subagent on `<engagement>/fuzzing`. Only `accepted` findings go to reporting.
