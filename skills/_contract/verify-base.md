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
3. **False-positive gauntlet** — domain-specific sanity checks (defined per skill in the inheriting `verify.md`) **plus the shared `counterevidence.md`**: a version/CVE match, "looks injectable", reflected metacharacters, a benign 500, or circular evidence are NOT proof. Is the effect real, or an inert reflection / benign error / honeypot / already-neutralized-by-a-filter case?
4. **Severity / CVSS integrity** — recompute the vector from the evidence per `severity-calibration.md`; do not trust the executor's number. Flag inflation, and guard against deflation (lower confidence, not severity, for unconfirmed reachability).
5. **Coverage audit** — cross-check against the executor's filled `OUT/checklist.md`: every item is `done`, or `skipped`/`blocked` **with a stated reason**. A silent gap is a finding against the executor. A candidate closed as "no issue" must be ruled out WITH evidence per `counterevidence.md` — the invalid-dismissal reasons there (a safe sibling, a too-late control, "internal-only", "couldn't build the PoC") do not count; missing information is not proof of safety. If `OUT/checklist.md` is absent, mark coverage `n/a` and flag that the executor didn't record it.
6. **Scope & safety compliance** — `asset` ∈ engagement scope: read `scope.yaml` (typically `OUT/../scope.yaml`); the action that produced it was within RoE; no destructive action occurred without approval. Out-of-scope ⇒ hard fail + flag. If `scope.yaml` is absent, mark scope `n/a` and flag it — never silently assume in-scope.
7. **Verdict + rework** — write a structured decision per finding.

## Verdict

A review emits a `review{}` object per finding, conforming to `finding.schema.json` → `review{}`.
It is a **closed** object (`additionalProperties:false`): the ONLY allowed keys are `verdict`,
`reviewer`, `reviewed_at`, `rubric`, `false_positive_checks`, `rejection_class`, `scope_ok`, `notes`.
`rubric` values are exactly `pass | fail | n/a`. The engagement gate (`verify_completion.py
--engagement`) HARD-fails any other key or value — so copy this shape exactly, and write the SAME
object to both the `reviews/<id>.verdict.json` file (below) and the inline `review{}` block.

```json
{
  "verdict": "accepted | rejected | needs-evidence | blocked",
  "reviewer": "<skill>-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["<what you ruled out>"],
  "scope_ok": true,
  "notes": "<terse — include your recomputed severity rating + its rationale here>"
}
```

When `verdict` is `rejected`, add `"rejection_class"` (`false-positive | out-of-scope | duplicate |
open-proof-gap` — see below). **Do not invent keys or values the schema forbids** — that is the single
biggest cause of rejected review blocks. The recurring offenders and their schema-valid homes:
- a recomputed severity rating has **no key of its own** → put it in `notes`, or (preferred, per
  `severity-calibration.md`) correct the finding's `severity` / `cvss_vector` / `potential_severity`
  and re-derive. There is **no `severity_opinion`** key.
- a half-met check is `fail` (name the weakness in `false_positive_checks` / `notes`), never
  `rubric: "weak"` / `"partial"`.
- "reachability confirmed, impact inferred" is the finding's `confidence: "probable"`, never `"firm"`.
- the finding id lives in the file name `reviews/<id>.verdict.json` and on the finding itself —
  **not inside `review{}`** (no `id` key).

### Two axes: `review.verdict` (the decision) vs finding `status` (the lifecycle)

These are **not** two names for the same thing — they are different axes, and conflating them is a recurring
confusion. `review.verdict` is the reviewer's **authoritative** decision (the `reviews/<id>.verdict.json`
file is the canonical record and the tiebreaker on any discrepancy). The finding's `status` is **derived**
from the verdict — do not set it independently. `duplicate`/`remediated` are lifecycle-only states (no
verdict equivalent), set downstream of review (de-dupe / retest).

| `review.verdict` | → finding `status` | reaches reporting? | meaning |
|------------------|--------------------|--------------------|---------|
| `accepted`       | `verified`         | yes                | confirmed |
| `blocked`        | `verified`         | yes, WITH a caveat | real, but full demonstration is prevented by env/target state |
| `rejected`       | `rejected`         | no                 | not real / out-of-scope / duplicate — set `rejection_class` |
| `needs-evidence` | `open`             | no — bounced back  | a missing artifact the executor can still produce |

The per-verdict rules below elaborate each row.

- `accepted` → finding `status: verified`.
- `rejected` → finding `status: rejected`; **set `rejection_class`** and state why. A `rejected` means *not a
  real vuln here*: `false-positive` (disproved WITH evidence), `out-of-scope`, or `duplicate` — a clean drop.
  It must **not** be used for a real-looking finding you simply could not prove here (missing PoC / creds /
  WAF / time): that is a `blocked` (when you are confident it is real) or `rejection_class: open-proof-gap`
  (when unsure). An **open-proof-gap is reported as a known gap / recall caveat — never silently dropped.**
  **Recall audit (the mode-6 guard):** when genuinely unsure between `false-positive` and `open-proof-gap`,
  choose **open-proof-gap**. A false positive is caught by a later reviewer; a false negative is invisible.
  `counterevidence.md`: "missing information is not proof of safety." The engagement gate
  (`verify_completion.py --engagement`) surfaces the open-proof-gap count so these stay visible.
- `needs-evidence` → a missing artifact the **executor can still produce** → bounce back and re-run that step.
- `blocked` → **confirmed real, but full demonstration is prevented by target/environment state the executor
  cannot change** (e.g. an unseeded DB blocking SQLi extraction). Set `status: verified`, record the
  demonstrated `severity` plus a `potential_severity`, and report it WITH a caveat — do **not** bounce it
  like `needs-evidence` (the re-run would be unsatisfiable).

### Where the verdict is written (concurrency-safe)

The orchestrator fans reviewers out in **parallel**. The race to avoid is two reviewers writing the **same**
`findings.json`. In Redstrike each skill owns its **own** `findings.json`, reviewed by its **own** dedicated
verifier — so a reviewer patching the `review{}` block + `status` of **its own skill's** `findings.json` is a
single-owner write and is race-free. The rules:

1. The reviewer ALWAYS writes `reviews/<id>.verdict.json` (one per finding) — the **canonical, authoritative**
   verdict record and the tiebreaker on any discrepancy.
2. The reviewer MAY also patch **its own skill's** `findings.json` (`review{}` + `status`) in the same pass
   (single-owner → safe), which is what each `verify.md`'s "write into the review{} block" step means. It
   MUST NOT write another skill's `findings.json` or any shared file.
3. The **orchestrator reconciles** (single authority across the engagement): it confirms every finding's
   `review{}`/`status` matches its verdict file (the verdict file wins), fills any the reviewer left
   unpatched, and sets `status` (accepted/blocked→verified, rejected→rejected, needs-evidence→open).

A reviewer MAY review **several findings in one pass** (e.g. all findings of a class) to cut cost — it still
writes one `reviews/<id>.verdict.json` per finding, and when it independently re-runs a benign PoC it logs
that request to `audit.jsonl` and respects the shared `rate_limit_rps`.

**Safeguard-safe framing (credential / token / crypto confirmations).** When re-confirming a weak-secret
finding (predictable/forgeable token, reused key/nonce, weak hash), confirm it via the DETERMINISTIC or
DISCLOSED value — e.g. show `hash(disclosed_preimage) == token` and that the recomputed value is accepted —
rather than framing the re-run as brute-forcing / forging / cracking. Same benign result, but phrasing a
credential check in weaponization terms can trip automated safety filters and abort the reviewer mid-run.
Keep payloads benign and read-only; prefer the smallest deterministic proof over search/enumeration.

### CVSS integrity

Recompute the vector deterministically with `scripts/cvss.py` — do not eyeball the score, and apply
`severity-calibration.md` to the metric choices (the High/Critical acceptance checklist + the anti-inflation
and deflation guards). If the computed rating differs from the declared `severity`, that is either inflation
(fix the metrics and re-derive — never hand-override the score) or a demonstrated-vs-potential gap (set
`potential_severity`). The consolidated gate (`verify_completion.py --engagement <dir>`) surfaces this drift
automatically.

Only `accepted` and `blocked` findings flow to the reporting skill (`blocked` strictly with its caveat).
