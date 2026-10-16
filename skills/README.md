# Redstrike Skills

Each skill is a self-contained quad (`SKILL.md` · `checklist.md` · `review.md` · `verify.md`? · `refs/`).
The contract, the two review altitudes, and how to build a new skill live in
[`_contract/README.md`](_contract/README.md). Pattern-match new skills against `js-analysis`.

| Skill | Kind | Emits findings? | Gates | Chains from → to |
|---|---|---|---|---|
| [`js-analysis`](js-analysis/) | recon (gold standard) | no | `review.md` | host-discovery → content-discovery, xss-* |
| [`xss-context`](xss-context/) | recon feeder (shared) | no | `review.md` | js-analysis → xss-reflected/stored/dom/blind |
| [`xss-reflected`](xss-reflected/) | vuln variant (reflected) | yes | `review.md` + `verify.md` | js-analysis / xss-context → reporting |
| [`xss-stored`](xss-stored/) | vuln variant (stored) | yes | `review.md` + `verify.md` | xss-context → reporting |
| [`xss-dom`](xss-dom/) | vuln variant (dom) | yes | `review.md` + `verify.md` | xss-context / js-analysis → reporting |
| [`xss-blind`](xss-blind/) | vuln variant (blind/OOB) | yes | `review.md` + `verify.md` | xss-context / xss-stored → reporting |

**Atomic single agents** (✅ built — same quint; statuses in [`_contract/vuln-catalog.md`](_contract/vuln-catalog.md)): `csrf` · `cors` · `open-redirect` · `clickjacking` · `host-header` · `request-smuggling` · `cache-poisoning` · `subdomain-takeover` · `security-headers` · `secrets` · `business-logic`

## Roadmap (same quad for each)
- **Recon feeders:** `host-discovery`, `content-discovery`  (`xss-context` ✅ built — shared XSS feeder)
- **XSS family:** ✅ complete — `xss-context` + `xss-reflected` + `xss-stored` + `xss-dom` + `xss-blind`
- **Every vuln category = its own agent:** see [`_contract/vuln-catalog.md`](_contract/vuln-catalog.md) — compound classes (SQLi, SSRF, access-control, …) decompose into a `<class>-context` feeder + variant agents (the XSS pattern); atomic classes (CSRF, open-redirect, …) are a single agent.
- **Agent tiers (recon → vuln categories → mission/capability agents):** see [`_contract/agent-tiers.md`](_contract/agent-tiers.md) — the "red team" layer (Bug Bounty, CTF Solver, CVE Intelligence, Exploit Generator, Attack Chain Discovery, Parameter Optimization) that composes the lower tiers.
- **Lifecycle spine:** `scope-and-roe`, `enumeration`, `vuln-analysis`, `exploitation`*, `post-exploitation`*, `reporting`  (`*` = active, import `_contract/roe-gate.md` + approval gate)
- **Meta:** `orchestrator` (reads `checklist.md` state + gate verdicts to advance phases; routes targets to category feeders per `_contract/vuln-catalog.md`)

## Run the mechanical gate
```bash
python skills/_contract/verify_completion.py --skill skills/<name> --out engagements/<client>-<date>/<name>/
```
