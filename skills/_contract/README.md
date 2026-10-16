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
2. Write `SKILL.md`: goal + definition-of-done, "what we want" tree, ordered **atomic** steps (`action · tool · output`), the tool table (modern-first + the [anti-automation ladder](anti-automation-ladder.md)), inputs, outputs, phases.
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

`review.md` is a **liveness/coverage** gate — an empty-but-valid `secrets.json` is a PASS (the step ran; it found nothing). Whether a finding is *true* is `verify.md`'s job, at a different altitude.

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

---

## Chaining

Skills chain through **files on disk**, declared in each `SKILL.md` (Inputs = chains FROM, Outputs = chains TO). Example: `js-analysis` writes `gadgets.md` + `endpoints_*.txt`; `xss-*` agents chain FROM them. Shared, reusable primitives (the fetch ladder, the finding schema, secret/sink corpora) live here in `_contract/` — define once, import everywhere.

## Vuln-category decomposition

When a skill's target is a vuln **class**, split it into one agent per variant (e.g. XSS → reflected / stored / dom / blind), each a full quad. Fan the variants out of a **shared context artifact** (e.g. `xss_context.json`, fed by `js-analysis/gadgets.md`) so they don't each re-derive injection points, sinks, and CSP.

## Governance (active skills only)

Recon is read-only. Any skill that sends a payload, exploits, or changes target state imports [`roe-gate.md`](roe-gate.md): hard scope allowlist check before acting, human approval gate for exploitation/post-exploitation, immutable audit log. The mechanical gate will NOT catch an out-of-scope action — that is the RoE gate's altitude.

## Claude Code / Agent SDK mapping

If you run Redstrike on the Claude Agent SDK: `SKILL.md` → a Skill, `verify.md` → a subagent (separate context is the point), `review.md` → a hook that shells out to `verify_completion.py`. The on-disk quad stays identical.
