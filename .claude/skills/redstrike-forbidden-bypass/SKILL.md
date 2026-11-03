---
name: redstrike-forbidden-bypass
description: Run the Redstrike forbidden / 403-bypass hunt (executor) — reach 401/403-restricted endpoints via path / method / header / protocol manipulation, confirmed by the REAL restricted content (not a bare 200), de-duped vs exposed-surface/auth-bypass — then gate and hand off to the forbidden-bypass-verify reviewer agent.
---

Run the Redstrike **forbidden-bypass** methodology (canonical spec: `skills/forbidden-bypass/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Read-only confirmation (reach the resource, don't dump it); benign loopback header values; no brute-force; raw HTTP client (no path normalization).
2. **Execute:** follow `skills/forbidden-bypass/SKILL.md`; collect the 401/403 inventory from `<engagement>/content-discovery/` (+ `host_discovery.json`); work `skills/forbidden-bypass/checklist.md`; use `skills/forbidden-bypass/refs/bypass_techniques.md`. Write outputs to `<engagement>/forbidden-bypass/`. (A reached admin/debug/actuator panel → `redstrike-exposed-surface` / `redstrike-privesc` for downstream impact.)
3. **Coverage:** copy your filled checklist into `<engagement>/forbidden-bypass/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/forbidden-bypass --out <engagement>/forbidden-bypass` → fix + re-run until exit 0.
5. **Reviewer:** launch the `forbidden-bypass-verify` subagent on `<engagement>/forbidden-bypass`. Only `accepted` findings go to reporting.
