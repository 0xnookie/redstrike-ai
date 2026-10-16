# verify-base — the semantic finding gate (inherited by every `verify.md`)

A `verify.md` exists ONLY for skills that emit `findings.json`. It runs as a
**subagent with its own fresh context** (an executor grading its own work inherits
its own blind spots — independence is the whole point). It consumes `findings.json`
+ the evidence vault and writes the `review{}` block of each finding
(see `finding.schema.json`), plus a verdict the orchestrator can act on.

> Precondition: the mechanical gate (`review.md` / `verify_completion.py`) has already PASSED.
> `verify.md` assumes the artifacts exist and are well-formed; it judges whether they're *true*.

## The 7 base checks (run per finding)

1. **Evidence sufficiency** — every finding cites a reproducible artifact in the vault (request/response, tool output, screenshot, DOM capture, PoC). No artifact ⇒ `verdict: rejected`. This single rule kills most hallucinations.
2. **Reproducibility** — the reproduction steps are concrete and re-runnable; a working PoC exists for Medium+. When feasible, **re-execute** the PoC and confirm the claimed effect.
3. **False-positive gauntlet** — domain-specific sanity checks (defined per skill in the inheriting `verify.md`). Is the effect real, or an inert reflection / benign error / honeypot / already-neutralized-by-a-filter case?
4. **Severity / CVSS integrity** — recompute the vector from the evidence; do not trust the executor's number. Flag inflation.
5. **Coverage audit** — cross-check against the executor's filled `OUT/checklist.md`: every item is `done`, or `skipped`/`blocked` **with a stated reason**. A silent gap is a finding against the executor. If `OUT/checklist.md` is absent, mark coverage `n/a` and flag that the executor didn't record it.
6. **Scope & safety compliance** — `asset` ∈ engagement scope: read `scope.yaml` (typically `OUT/../scope.yaml`); the action that produced it was within RoE; no destructive action occurred without approval. Out-of-scope ⇒ hard fail + flag. If `scope.yaml` is absent, mark scope `n/a` and flag it — never silently assume in-scope.
7. **Verdict + rework** — write a structured decision per finding.

## Verdict (write into each finding's `review{}` block)

```json
"review": {
  "verdict": "accepted | rejected | needs-evidence",
  "reviewer": "<skill>-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["<what you ruled out>"],
  "scope_ok": true,
  "notes": "<terse>"
}
```

- `accepted` → set finding `status: verified`.
- `rejected` → set finding `status: rejected`; state why.
- `needs-evidence` → bounce back to the executor with the specific missing artifact; re-run that step.

Only `accepted` findings flow to the reporting skill.
