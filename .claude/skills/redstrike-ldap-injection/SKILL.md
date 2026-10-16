---
name: redstrike-ldap-injection
description: Run the Redstrike LDAP injection hunt (executor) — filter-metacharacter injection into LDAP search queries for auth bypass or directory enumeration, confirmed benignly — then gate and hand off to the ldap-injection-verify reviewer agent.
---

Run the Redstrike **ldap-injection** methodology (canonical spec: `skills/ldap-injection/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; approval required; use a test account; benign + minimal — no bulk directory dump; rate-limit wildcard queries.
2. **Execute:** follow `skills/ldap-injection/SKILL.md`; consume `skills/js-analysis/` params (login/search/filter) + `tech.md` (LDAP/AD-backed); work `skills/ldap-injection/checklist.md`; use `skills/ldap-injection/refs/`. Write outputs to `<engagement>/ldap-injection/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ldap-injection/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ldap-injection --out <engagement>/ldap-injection` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ldap-injection-verify` subagent on `<engagement>/ldap-injection`. Only `accepted` findings go to reporting.
