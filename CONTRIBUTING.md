# Contributing to Redstrike AI

Every skill follows ONE contract: **[`skills/_contract/README.md`](skills/_contract/README.md)** — read it first.
Pattern-match new skills against the gold standard [`skills/js-analysis/`](skills/js-analysis/) (recon) or a
findings-producing agent like [`skills/xss-reflected/`](skills/xss-reflected/).

## Adding a skill (the quad/quint)

1. Run the design interview ([`_contract/interview-template.md`](skills/_contract/interview-template.md)) and paste the answers at the top of `SKILL.md`.
2. Write `SKILL.md` + `checklist.md` (load-bearing: `- [ ]` = re-run) + `review.md` (with an embedded ```json manifest the verifier consumes).
3. If it emits `findings.json`: add `verify.md` (inherit [`_contract/verify-base.md`](skills/_contract/verify-base.md)) **and** register a reviewer subagent at `.claude/agents/<skill>-verify.md`.
4. Add a Claude Code binding at `.claude/skills/redstrike-<skill>/SKILL.md`.
5. Add a row to [`_contract/vuln-catalog.md`](skills/_contract/vuln-catalog.md).
6. Active skills (anything that sends a payload) import [`_contract/roe-gate.md`](skills/_contract/roe-gate.md).

## Before you open a PR

```bash
python scripts/validate.py                                             # must pass (CI runs this)
python skills/_contract/verify_completion.py --skill skills/<skill> --out <test-out>
```

CI ([`.github/workflows/validate.yml`](.github/workflows/validate.yml)) validates every skill's manifest, the JSON schemas, and agent/skill frontmatter on every push/PR.

## Conventions

- **Two-altitude review** is non-negotiable: `review.md` (mechanical, a script) + `verify.md` (semantic, an independent subagent). The reviewer is an agent, not more instructions.
- Modern-tool-first; reference [`_contract/anti-automation-ladder.md`](skills/_contract/anti-automation-ladder.md) rather than re-describing the fetch ladder.
- Compound vuln classes → a `<class>-context` feeder + per-variant agents (the XSS pattern). Atomic classes → a single agent.
- Keep engagement data OUT of git (`engagements/` is ignored except the scope template).

---

Authorized testing only. By contributing you confirm your skills are for lawful, authorized security work.
