# Redstrike Skill Contract

Every Redstrike skill is a self-contained **quad** (recon skills drop the 4th file):

```
<skill-name>/
  SKILL.md       # design-interview header + goal · steps · tools · I/O · phases
  checklist.md   # load-bearing completion ledger (state, not docs)
  review.md      # MECHANICAL completion gate  (+ embedded JSON manifest for the verifier)
  verify.md      # SEMANTIC finding gate       — ONLY if the skill emits findings.json
  refs/          # optional RAG corpus: regexes, wordlists, payloads, good samples
```

Pattern-match every new skill against the gold standard: [`../js-analysis/`](../js-analysis/).
A findings-producing skill with both review altitudes: [`../xss-reflected/`](../xss-reflected/).

---

## Build order for a new skill

1. Run the **design interview** ([`interview-template.md`](interview-template.md)) and paste the answers at the top of `SKILL.md`. Do this FIRST — before writing steps.
2. Write `SKILL.md`: goal + definition-of-done, "what we want" tree, ordered **atomic** steps (`action · tool · output`), the tool table (modern-first + the [anti-automation ladder](anti-automation-ladder.md); **tool-first** — [`tooling.md`](tooling.md), never hand-roll what a standard tool does), inputs, outputs, phases.
3. Write `checklist.md`: mirror the steps 1:1. Semantics are load-bearing (below).
4. Write `review.md`: per-step artifact checks + an embedded ```json manifest the [verifier](verify_completion.py) consumes. Inherit [`review-base.md`](review-base.md).
5. If (and only if) the skill emits `findings.json`, write `verify.md`, inheriting [`verify-base.md`](verify-base.md). Recon skills skip this.
6. Seed `refs/` with any corpus the steps reference.

> **Golden rule:** every step is atomic and MUST emit at least one artifact. The artifact is the proof the step ran — no silent work.

---

## The two review altitudes

These are different gates. Do not fuse them.

| | `review.md` (mechanical) | `verify.md` (semantic) |
|---|---|---|
| Question | Did every step run and emit well-formed output? | Is each finding real, reproducible, in-scope, correctly rated? |
| Nature | Deterministic — exists · non-zero · valid format · plausible size | LLM judgment, evidence → claim |
| Runs as | A script ([`verify_completion.py`](verify_completion.py)) | A subagent with its own fresh context |
| Catches | Execution false-**negatives** (silent failure, empty output) | Analytical false-**positives** (hallucinated vuln) + scope/safety violations |
| Applies to | **every** skill | **only** findings-producing skills |

`review.md` is a **liveness/coverage** gate — an empty-but-valid `findings/secrets.jsonl` is a PASS (the step ran; it found nothing). Whether a finding is *true* is `verify.md`'s job, at a different altitude.

**Executor-side rigor — front-load it ([`counterevidence.md`](counterevidence.md)).** Before an executor
emits a finding, or marks a surface tested-and-clear, it argues the opposing case: re-trigger via a
*different* path, state assumptions + the constraints actually hit, and close each candidate as
**confirmed / ruled-out-with-evidence / open-proof-gap** (never silently drop one). This kills junk findings
*before* the reviewer and stops a real candidate being dismissed for an invalid reason; the `verify.md`
reviewer then re-checks it (base checks #3/#5). Rating follows [`severity-calibration.md`](severity-calibration.md).

---

## `checklist.md` semantics (LOAD-BEARING)

- `- [ ]` = **NOT done** → the agent did not finish this → the step MUST be re-run.
- `- [x]` = done.
- Sections use `##`; nest sub-steps with indentation; links allowed in items.

The checklist is **state**, not documentation. The control loop is: run step → mark `[x]` only when its artifact exists → `review.md`/the verifier re-checks → any `[ ]` (or any failed artifact check) ⇒ re-run that step. The orchestrator reads this file to decide re-run vs. advance.

---

## `review.md` is executable

Each `review.md` embeds a fenced ```json **manifest** (`manifest_version`, `artifacts[]`). Run the deterministic gate with:

```bash
python skills/_contract/verify_completion.py --skill skills/js-analysis --out <engagement_out_dir>
```

Exit code `0` = PASS, `2` = at least one required artifact missing/empty/malformed (⇒ re-run those steps). The human-readable checkboxes in `review.md` and the manifest describe the same checks — the prose is for people, the manifest is for the loop.

### Consolidated engagement mode

An orchestrator-led engagement keeps **one** shared `findings.json` + a single evidence vault
(`findings/evidence/`, `findings/poc/`) + one `reviews/<id>.verdict.json` per finding, instead of a per-skill
OUT dir. Validate that layout with:

```bash
python skills/_contract/verify_completion.py --engagement engagements/<client>-<date>
```

It is the deterministic altitude for the consolidated layout: every finding must cite at least one evidence
artifact that exists and is non-empty (the pre-review **hygiene lint**), and it soft-warns on CVSS/severity
drift, out-of-scope assets, and missing reviewer verdicts (warnings never fail the gate; a missing/empty
evidence ref or a malformed finding does). Per-skill `--skill/--out` mode is unchanged.

### Deterministic CVSS

Scores are computed, never hand-asserted: [`../../scripts/cvss.py`](../../scripts/cvss.py) turns a CVSS 3.1
vector into a base score + rating (`python scripts/cvss.py "CVSS:3.1/…"`). Executors and `reporting` use it;
`verify.md` recomputes with it; the consolidated gate and `validate.py` call it to flag drift. When the
demonstrated `severity` is deliberately below the vector's rating (e.g. a confirmed injection point whose
extraction was environment-blocked), record a `potential_severity` so the gap is explicit, not an error.

---

## Chaining

Skills chain through **files on disk**, declared in each `SKILL.md` (Inputs = chains FROM, Outputs = chains TO). Example: `js-analysis` writes `findings/gadgets.jsonl` + `findings/endpoints.jsonl`; `xss-*` agents chain FROM them. Shared, reusable primitives (the fetch ladder, the finding schema, secret/sink corpora, the **tool roster + tool-first rule** in [`tooling.md`](tooling.md)) live here in `_contract/` — define once, import everywhere.

## Vuln-category decomposition

When a skill's target is a vuln **class**, split it into one agent per variant (e.g. XSS → reflected / stored / dom / blind), each a full quad. Fan the variants out of a **shared context artifact** (e.g. `xss_context.json`, fed by `js-analysis/out/<site>/findings/gadgets.jsonl`) so they don't each re-derive injection points, sinks, and CSP.

## Single-class hunters

A **hunter** (`<class>-hunter`, e.g. `xss-hunter`) is a Tier-3 MISSION agent that drives the whole pipeline toward ONE vuln class, depth-first — `bug-bounty` pinned to a class. It **reuses** the class's `<class>-context` feeder, its executors + `*-verify` reviewers, and `reporting` packaging; it emits no findings of its own (`review.md` only, no `verify.md`). The shared 80% (scope, gated hunt, triage, packaging, safety) lives in [`hunter-base.md`](hunter-base.md); each per-class `SKILL.md` adds only the thin CLASS BLOCK (recon surface · feeder · executor set · escalation ref · chains), so a new hunter is a ~30-line clone. A hunter never duplicates an executor or reviewer — it is a thin wrapper, not a fork.

## Governance (active skills only)

Recon is read-only. Any skill that sends a payload, exploits, or changes target state imports [`roe-gate.md`](roe-gate.md): hard scope allowlist check before acting, human approval gate for exploitation/post-exploitation, immutable audit log. The mechanical gate will NOT catch an out-of-scope action — that is the RoE gate's altitude.

## Claude Code / Agent SDK mapping

If you run Redstrike on the Claude Agent SDK: `SKILL.md` → a Skill, `verify.md` → a subagent (separate context is the point), `review.md` → a hook that shells out to `verify_completion.py`. The on-disk quad stays identical.
