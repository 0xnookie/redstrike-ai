# Redstrike Skills

Each skill is a self-contained quad (`SKILL.md` · `checklist.md` · `review.md` · `verify.md`? · `refs/`).
The contract, the two review altitudes, and how to build a new skill live in
[`_contract/README.md`](_contract/README.md). Pattern-match new skills against `js-analysis`.

| Skill | Kind | Emits findings? | Gates | Chains from → to |
|---|---|---|---|---|
| [`js-analysis`](js-analysis/) | recon (gold standard) | no | `review.md` | host-discovery → content-discovery, xss-* |
| [`xss-reflected`](xss-reflected/) | vuln variant (reflected) | yes | `review.md` + `verify.md` | js-analysis / xss-context → reporting |

## Roadmap (same quad for each)
- **Recon feeders:** `host-discovery`, `content-discovery`, `xss-context` (shared XSS feeder)
- **XSS siblings:** `xss-stored`, `xss-dom`, `xss-blind`
- **Other vuln classes:** `ssrf`, `idor`, `sqli`, `ssti`, `access-control`
- **Lifecycle spine:** `scope-and-roe`, `enumeration`, `vuln-analysis`, `exploitation`*, `post-exploitation`*, `reporting`  (`*` = active, import `_contract/roe-gate.md` + approval gate)
- **Meta:** `orchestrator` (reads `checklist.md` state + gate verdicts to advance phases)

## Run the mechanical gate
```bash
python skills/_contract/verify_completion.py --skill skills/<name> --out engagements/<client>-<date>/<name>/
```
