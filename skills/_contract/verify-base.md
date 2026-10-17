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

## Verdict

A review emits this object per finding (schema: `finding.schema.json` → `review{}`):

```json
{
  "id": "RS-YYYY-NNN",
  "verdict": "accepted | rejected | needs-evidence | blocked",
  "reviewer": "<skill>-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["<what you ruled out>"],
  "scope_ok": true,
  "severity_opinion": "<your recomputed rating>",
  "notes": "<terse>"
}
```

- `accepted` → finding `status: verified`.
- `rejected` → finding `status: rejected`; state why.
- `needs-evidence` → a missing artifact the **executor can still produce** → bounce back and re-run that step.
- `blocked` → **confirmed real, but full demonstration is prevented by target/environment state the executor
  cannot change** (e.g. an unseeded DB blocking SQLi extraction). Set `status: verified`, record the
  demonstrated `severity` plus a `potential_severity`, and report it WITH a caveat — do **not** bounce it
  like `needs-evidence` (the re-run would be unsatisfiable).

### Where the verdict is written (concurrency-safe)

The orchestrator fans reviewers out in **parallel**, so a reviewer MUST NOT patch the shared `findings.json`
directly (that races other reviewers). Instead:

1. The reviewer writes **only** `reviews/<id>.verdict.json` (one file per finding) in the engagement dir.
2. The **orchestrator merges** every `reviews/*.verdict.json` into each finding's `review{}` block and sets
   `status` (accepted/blocked→verified, rejected→rejected, needs-evidence→open). This is the single writer.

A reviewer MAY review **several findings in one pass** (e.g. all findings of a class) to cut cost — it still
writes one `reviews/<id>.verdict.json` per finding, and when it independently re-runs a benign PoC it logs
that request to `audit.jsonl` and respects the shared `rate_limit_rps`.

### CVSS integrity

Recompute the vector deterministically with `scripts/cvss.py` — do not eyeball the score. If the computed
rating differs from the declared `severity`, that is either inflation (fix it) or a demonstrated-vs-potential
gap (set `potential_severity`). The consolidated gate
(`verify_completion.py --engagement <dir>`) surfaces this drift automatically.

Only `accepted` and `blocked` findings flow to the reporting skill (`blocked` strictly with its caveat).
