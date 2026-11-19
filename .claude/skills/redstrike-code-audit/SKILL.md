---
name: redstrike-code-audit
description: Run the Redstrike code-audit white-box executor — audit a whole authorized source repository for vulnerabilities by REASONING beyond grep (model the app, then inter-procedural framework-aware taint across files/functions + authz/logic/crypto/race reasoning), CONFIRM or refute each source-audit lead by reading the real code path, CHAIN confirmed weaknesses into kill-chains, and emit source-informed fuzz targets — producing confirmed, calibrated findings.json gated by the code-audit-verify reviewer. Consumes source_context.json; does NOT re-grep or replace source-audit. Approval-gated for any dynamic PoC/fuzz-harness run.
---

Run the Redstrike **code-audit** executor (canonical spec: `skills/code-audit/`). White-box PROVING over an
authorized source repository.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Requires a
   `scope.source` block (white-box / source-granted signal); resolve the repo from `scope.source.local_path`
   (default `engagements/<id>/source/`). Static reasoning is **read-only** — never execute the source while
   modeling/tracing. Any **dynamic** step (a PoC driver, a benign dynamic confirmation) is **approval-required**
   and runs only against an authorized/sandboxed instance. Redact secret VALUES to fingerprints.
2. **Execute:** follow `skills/code-audit/SKILL.md`; consume `<engagement>/source-audit/source_context.json`
   (routed candidates + `chain_candidates[]` + `structural[]`) as high-confidence LEADS and the repo source.
   Model the app (entry points / trust boundaries / auth model / data stores / privileged ops → `app_model.json`),
   run inter-procedural framework-aware taint + non-grep class reasoning (authz / logic / crypto / races /
   mass-assign) to CONFIRM or refute each lead by reading the real code path (`analysis.jsonl`), close each
   candidate confirmed / ruled-out / open-proof-gap per `skills/_contract/counterevidence.md`, chain confirmed
   legs into kill-chains (`chains.jsonl`), and emit source-informed fuzz targets (`fuzz_targets.jsonl`, shape in
   `skills/code-audit/refs/source_informed_fuzzing.md`). Work `skills/code-audit/checklist.md`; use
   `skills/code-audit/refs/`. A finding REQUIRES the white-box evidence standard — a traced reachable path at
   `file:line` across the call chain AND a PoC/exploit sketch (or executed PoC / fuzz crash); confidence is
   calibrated (static-only ⇒ `probable` + runtime-guard caveat). Write outputs to `<engagement>/code-audit/`.
3. **Fuzz hand-off:** `fuzz_targets.jsonl` is handed to the `redstrike-fuzzing` skill as white-box seed targets
   (it runs / minimizes / triages / proves the crash, gated by `fuzzing-verify`) — this skill does NOT run the
   fuzzer.
4. **Coverage:** copy your filled checklist into `<engagement>/code-audit/checklist.md`.
5. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/code-audit --out <engagement>/code-audit` → fix + re-run until exit 0.
6. **Reviewer:** launch the `code-audit-verify` subagent on `<engagement>/code-audit`. It rejects grep-asserted
   findings (no traced path), over-claimed runtime proof, and chains with unconfirmed legs. Only `accepted`
   (and `blocked`, with a caveat) findings go to reporting.
