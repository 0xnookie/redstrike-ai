# Fuzzing Agent

> ATOMIC agent — coverage-guided + structure-aware fuzzing of an authorized target (binary / library / parser / network-API) to surface reproducible crashes.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (fuzzing can crash live services). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** pick target + build an instrumented harness (ASAN/UBSAN + coverage) → seed corpus + dictionary → run a coverage-guided fuzzer (AFL++/libFuzzer/honggfuzz) OR a network/API fuzzer (boofuzz/RESTler) → collect crashes → triage bug class (`exploitable`/crashwalk) + dedup → minimize the crashing input → reproduce deterministically → rate → emit → review → verify.
- **TOOLS:** AFL++, libFuzzer, honggfuzz, boofuzz, RESTler, ASAN/UBSAN, afl-tmin, crashwalk/`exploitable`, `refs/fuzzing_techniques.md`.
- **GOAL:** Confirm a reproducible memory-safety / crash defect on an authorized target — a MINIMIZED input that deterministically triggers a sanitizer-detected fault (ASAN/UBSAN trace) — the crash IS the finding. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `fuzz_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = an authorized target (binary/library/parser/network or REST API) + its input format + `scope.yaml`. `refs/` = `fuzzing_techniques.md`. Chains FROM recon / target intake; chains TO `exploit-dev` + `reporting`.
- **DECOMPOSITION:** n/a (atomic; harness/target recipes in refs).

## Goal
Prove a reproducible crash on an authorized target (minimized input + sanitizer trace). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The target + its input surface (file format, API/protocol, library entry point) and an instrumented build (ASAN/UBSAN) or a black-box harness
- A coverage-guided or structure-aware campaign with a seed corpus + dictionary driving a crash
- A benign proof: a MINIMIZED input that deterministically reproduces a sanitizer-detected fault, deduped to a unique root cause — not a flaky one-off

## Steps  (action · tool · output)
1. Define target + input format; build an instrumented harness (ASAN/UBSAN + coverage) · build + refs · `logs/`
2. Assemble a seed corpus + dictionary (valid samples, grammar tokens) · refs · `logs/`
3. Run coverage-guided fuzzer (AFL++/libFuzzer/honggfuzz) OR network/API fuzzer (boofuzz/RESTler) · fuzzer · `fuzz_tests.jsonl`
4. Collect crashes; triage bug class (ASAN/UBSAN, `exploitable`/crashwalk) · triage · `fuzz_tests.jsonl`
5. Dedup (unique stack hashes) + minimize the crashing input (afl-tmin) · tooling · `poc/<id>/`
6. Reproduce deterministically from the minimized input · harness · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report · synth · `report.md` · 9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- AFL++, libFuzzer, honggfuzz, boofuzz, RESTler, ASAN/UBSAN, afl-tmin, crashwalk/`exploitable`, `refs/fuzzing_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- An authorized target (binary / library / parser / network or REST API) + its input format + `scope.yaml`

## Outputs
`fuzz_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** harness + corpus + fuzz campaign → raw crashes.
- **Phase 2 (target-specific):** triage + dedup + minimization + deterministic repro + rating (approval-gated).

## Safety
Fuzzing crashes things — **approval-gated**; fuzz a dedicated/authorized instance, **not** shared production
(a live API campaign can DoS). Prefer an offline/instrumented copy; rate-limit network fuzzing. The proof is a
MINIMIZED input + sanitizer trace, **not** a weaponized exploit (hand a controlled crash to `exploit-dev`).
Keep inputs benign; scope-gate (in-scope host/binary only); audit-log; honor the kill switch.
