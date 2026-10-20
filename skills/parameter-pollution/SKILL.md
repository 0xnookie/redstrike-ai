# HTTP Parameter Pollution Agent

> ATOMIC single agent (no feeder) — duplicate/polluted parameters exploiting parser precedence discrepancies.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** map params + layers (gateway vs backend) → inject duplicates across sources (URL / body / JSON / cookie / header, array notation, cloaking) → determine which layer parses which value → exploit a security decision (authz / value override / control bypass / WAF or filter smuggling) → confirm benignly → rate → emit → review → verify.
- **TOOLS:** interceptor, Param Miner (hidden params), `refs/hpp_techniques.md` (parser-precedence table).
- **GOAL:** Confirm HTTP Parameter Pollution with impact — a duplicated/polluted parameter changes a security-relevant decision because a front layer and the backend disagree on which value wins. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `hpp_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/params.jsonl` + `content-discovery` + `js-analysis/out/<site>/analysis/site-summary.md` (stack → parser behaviour) + `scope.yaml`. `refs/` = `hpp_techniques.md`. Chains FROM recon; feeds/overlaps `access-control`, `ssrf`, `request-smuggling`, `oauth`, `waf-bypass`; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove HPP with a security consequence (not cosmetic duplication). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- A parameter that reaches a security decision (authz flag, identity, price, redirect, filter input)
- A parser discrepancy: the gateway/WAF/validator reads one occurrence, the backend reads another
- A benign proof: the duplicated/polluted value flips the decision (e.g. `admin=false&admin=true` grants, a WAF-inspected first value passes while the backend uses the malicious second)

## Steps  (action · tool · output)
1. Ingest params + fingerprint stack (parser precedence) · `jq` + `site-summary.md` · (into tests)
2. Inject duplicates per source: URL `?p=a&p=b`, body, JSON `{"p":"a","p":"b"}`, cookie, header · interceptor + refs · `hpp_tests.jsonl`
3. Array/notation variants (`p[]=`, `p[0]=`) + cloaking (`par%61m`, case, `%00`, double-encode) · refs · `hpp_tests.jsonl`
4. Determine precedence (which value the response reflects/acts on) per layer · interceptor · `hpp_tests.jsonl`
5. Exploit a decision: authz (`access=false&access=true`), identity (`user=victim&user=admin`), WAF/filter smuggle, SSRF (`url=ok&url=internal`), OAuth (`redirect_uri` dup), SSPP (inject `%26`/`%23` into a value forwarded to an internal API) · refs · `poc/<id>/`
6. Confirm benignly (decision flipped, test identities) · synth · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- interceptor, Param Miner, `refs/hpp_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/params.jsonl`, `content-discovery`, `js-analysis/out/<site>/analysis/site-summary.md`, `scope.yaml`

## Outputs
`hpp_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** precedence mapping across sources + layers.
- **Phase 2 (target-specific):** flip a security decision + rating.

## Safety
Benign: flip a decision on TEST identities and prove it — no real-account authz changes without approval.
When HPP is used to smuggle another payload (SQLi/SSRF/XSS), hand the confirmed vector to that agent and
use ITS benign-proof rules. Scope-gate; audit-log.
