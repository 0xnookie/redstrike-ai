---
name: redstrike-idor
description: Run the Redstrike IDOR hunt (executor) — object-level access control: account A reaches account B's resource (incl. mass-assignment) — then gate and hand off to the idor-verify reviewer agent.
---

Run the Redstrike **idor** methodology (canonical spec: `skills/idor/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Use TWO TEST accounts you control (A, B) — **never access a real user's data** to prove IDOR; modifications on a test resource only, reversible.
2. **Execute:** follow `skills/idor/SKILL.md`; consume `<engagement>/authz-context/authz_context.json` (objects, mass-assign) + `auth.env` (≥2 identities); work `skills/idor/checklist.md`; use `skills/authz-context/refs/`. Write outputs to `<engagement>/idor/`.
3. **Coverage:** copy your filled checklist into `<engagement>/idor/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/idor --out <engagement>/idor` → fix + re-run until exit 0.
5. **Reviewer:** launch the `idor-verify` subagent on `<engagement>/idor`. Only `accepted` findings go to reporting.
