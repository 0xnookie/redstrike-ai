# Code Audit — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Repo resolved from `scope.source.local_path` (default `engagements/<id>/source/`) + in-scope confirmed
- [ ] RoE honored; approval obtained BEFORE any dynamic PoC / fuzz-harness run (static reasoning is read-only)
- [ ] `source-audit/source_context.json` leads ingested (candidates + chain_candidates[] + structural[])

## Model
- [ ] App model built: entry points, trust boundaries, auth/session model, data stores, privileged ops → app_model.json

## Reason (beyond grep)
- [ ] Inter-procedural taint: each lead traced source→sink across files/functions; sanitizers/guards/auto-escape on the path named
- [ ] Each lead closed confirmed / ruled-out / open-proof-gap (a grep hit with no traced path is REFUTED, not kept)
- [ ] Non-grep classes reasoned vs the app model: authz (object + function-level), logic invariants, insecure defaults, crypto/deser misuse, SSRF, path traversal, injection, race conditions, mass assignment
- [ ] Counterevidence pass run (negative control where feasible); runtime-guard uncertainty recorded per candidate

## Demonstrate (white-box evidence standard)
- [ ] Each finding carries a traced reachable path at file:line AND a PoC/exploit sketch (or an executed PoC / fuzz-triggered crash)
- [ ] Confidence calibrated: static-only path ⇒ `probable` + runtime-guard caveat; `confirmed` only with dynamic proof
- [ ] CVSS rated (scripts/cvss.py) with potential_severity where a precondition blocked full demonstration

## Chain
- [ ] Confirmed weaknesses composed into kill-chains, EACH leg a confirmed finding → chains.jsonl
- [ ] No padded chains — any chain with an unconfirmed leg was dropped

## Fuzz hand-off
- [ ] Fuzzable entry points picked from source + confirmed candidates
- [ ] Per-language harness stubs + input grammar/seed hints emitted → fuzz_targets.jsonl (handed to the fuzzing skill)

## Emit
- [ ] findings.json (schema-valid; empty array → a clean repo is a valid PASS)
- [ ] poc/ per finding (trace + PoC sketch / dynamic evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
