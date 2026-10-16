# LDAP Injection Agent

> ATOMIC single agent (no feeder) — filter injection into LDAP search queries (auth bypass, enumeration).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.
## Interview
- **STEPS:** ingest params (login, search) → detect LDAP backend → filter injection (auth bypass `*)(uid=*))(|(uid=*`) → wildcard enumeration → blind (boolean by attribute presence) → confirm (auth bypass / enumeration, benign) → rate → emit → review → verify.
- **TOOLS:** interceptor, `refs/ldap_payloads.md`.
- **GOAL:** Confirm LDAP injection — filter manipulation that bypasses authentication or enumerates directory data — benignly. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `ldap_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/params.txt` (login/search/filter params) + `tech.md` (LDAP/AD-backed) + `scope.yaml`. `refs/` = `ldap_payloads.md`. Chains FROM recon; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove LDAP injection (auth bypass / enumeration), benign. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- Params that reach an LDAP search filter (login, user search, group lookup)
- The vector: filter breakout (`)(`, `*`, `|`, `&`) injected into the filter
- A benign proof: auth bypass, or wildcard enumeration returning more entries than intended

## Steps  (action · tool · output)
1. Ingest login/search params + LDAP fingerprint · `jq`/`grep` + `tech.md` · (into tests)
2. Auth-bypass filter injection (`*`, `*)(uid=*))(|(uid=*`, `admin)(&)`) · interceptor + refs · `ldap_tests.jsonl`
3. Wildcard enumeration (`*` in search) · refs · `ldap_tests.jsonl`
4. Blind boolean (attribute presence: `)(attr=value*)` true/false) · refs · `ldap_tests.jsonl`
5. Confirm (auth bypass / enumeration) benignly · interceptor · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, `refs/ldap_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/params.txt`, `tech.md`, `scope.yaml`

## Outputs
`ldap_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** filter-injection auth bypass.
- **Phase 2 (target-specific):** wildcard enumeration + blind + rating (approval-gated).

## Safety
Benign: prove auth bypass or minimal enumeration — **no** bulk directory dump; wildcard queries can be
heavy, so rate-limit. Approval-gated; scope-gate; audit-log.
