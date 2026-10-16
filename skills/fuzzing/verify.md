# Fuzzing — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the fuzzing gauntlet. Confirmed = a minimized input DETERMINISTICALLY reproduces a
real sanitizer-detected fault on the authorized target. Re-run the minimized repro.

## Fuzzing false-positive gauntlet (base check #3)
- [ ] **Crash is real + reproducible.** The minimized input triggers the fault on demand (≥2 clean runs),
      with an ASAN/UBSAN (or debugger) trace showing the faulting operation — not a flaky one-off or a
      harness/OOM artifact.
- [ ] **It's a target defect, not a harness bug.** The fault is in the target code, not in the fuzzing
      harness/driver, an intended assert, or resource exhaustion (ulimit/OOM) misread as a bug.
- [ ] **Deduped to a unique root cause.** Reported crashes map to distinct root causes (stack-hash /
      faulting frame), not N duplicates of one bug inflating the count.
- [ ] **Benign + minimized.** The PoC is a minimized crashing input + trace on an authorized instance —
      NOT a weaponized exploit (control-of-execution belongs to `exploit-dev`); no production DoS.
- [ ] **Scope + approval.**

## CVSS integrity
Rate from the demonstrated bug class + reachability: a reachable memory-corruption (heap/stack overflow,
use-after-free) → High/Critical; a NULL-deref / assert DoS → Medium, unless remote + unauthenticated.
Exploitability is assessed honestly (potential ≠ proven) — a weaponized PoC is `exploit-dev`'s job.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "fuzzing-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["minimized 48-byte input reproduces heap-buffer-overflow READ in parse_tag() over 3/3 runs; ASAN trace attached; unique stack-hash; authorized test instance"],
  "scope_ok": true, "notes": "minimized repro + ASAN trace; benign crash only; exploitability potential noted, not weaponized; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
