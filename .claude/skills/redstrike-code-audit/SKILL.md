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
   Model the app (entry points / trust boundaries / auth model / data stores / privileged ops → `app_model.json`).
   **Inventory the FULL white-box surface** into the engagement surface ledger —
   `python scripts/surface.py --plan --engagement <engagement>` enumerates every entry point (from
   `app_model.json`) + every `source_context.json` lead + every high-risk file + every state-changing
   op×invariant (`state-op`, from `app_model.state_ops`) + every route×required-privilege cell (`authz-route`,
   from `app_model.authz_routes`) as surface routed to `code-audit` (idempotent; re-run as you find more). Then
   run inter-procedural framework-aware taint + non-grep class reasoning to CONFIRM or refute each lead by
   reading the real code path (`analysis.jsonl`) — INCLUDING the two first-class enumerated passes grep/taint
   can't see: the **business-logic & concurrency invariant** pass (§3a — break each `state-op`'s invariant:
   check-then-act with no lock/atomic update/unique constraint = TOCTOU, double-spend, client-trusted values
   re-derived server-side) and the **authorization matrix** pass (§3b — each `authz-route` cell: a
   state-changing/sensitive route with NO authz, or one that bypasses a central authz backstop via a
   service/queue/raw-SQL call) — close each
   candidate confirmed / ruled-out / open-proof-gap per `skills/_contract/counterevidence.md`, and as you close
   each surface element MARK it (`scripts/surface.py --mark <id> --status tested --by code-audit --reason "…"`,
   or `--status skipped --reason "…"` — nothing silently untested). Chain confirmed
   legs into kill-chains (`chains.jsonl`), and emit source-informed fuzz targets (`fuzz_targets.jsonl`, shape in
   `skills/code-audit/refs/source_informed_fuzzing.md`). For a huge repo, use a risk-prioritized, chunked plan so
   size never causes a silent skip. Work `skills/code-audit/checklist.md`; use
   `skills/code-audit/refs/`. A finding REQUIRES the white-box evidence standard — a traced reachable path at
   `file:line` across the call chain AND a PoC/exploit sketch (or executed PoC / fuzz crash); confidence is
   calibrated (static-only ⇒ `probable` + runtime-guard caveat). Write outputs to `<engagement>/code-audit/`.
3. **Fuzz hand-off:** `fuzz_targets.jsonl` is handed to the `redstrike-fuzzing` skill as white-box seed targets
   (it runs / minimizes / triages / proves the crash, gated by `fuzzing-verify`) — this skill does NOT run the
   fuzzer.
4. **Completeness gate + re-convergence:** fold in surface found mid-audit (append to `app_model.json` /
   `<engagement>/reconvergence/inbox.jsonl`, then re-run the `--plan`), then
   `python scripts/surface.py --validate --engagement <engagement> --routed-to code-audit --strict` → every
   entry point / lead / high-risk file / state-op / authz-route must be `tested` or reasoned-`skipped`. Any
   remaining `discovered`
   element is a RECALL GAP — close it, or report it as EXPLICIT partial coverage (coverage %, what's pending) in
   `report.md`. Never present partial coverage as complete; never claim clean over untested surface.
5. **Coverage:** copy your filled checklist into `<engagement>/code-audit/checklist.md`.
6. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/code-audit --out <engagement>/code-audit` → fix + re-run until exit 0.
7. **Reviewer:** launch the `code-audit-verify` subagent on `<engagement>/code-audit`. It rejects grep-asserted
   findings (no traced path), over-claimed runtime proof, and chains with unconfirmed legs, AND fails
   `rubric.coverage` (bouncing the run) when the surface ledger was never enumerated or left `code-audit`
   surface untested with no reason — so a clean/empty report can't ship over untested surface. Only `accepted`
   (and `blocked`, with a caveat) findings go to reporting.
