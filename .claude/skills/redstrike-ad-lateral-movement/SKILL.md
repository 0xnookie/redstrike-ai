---
name: redstrike-ad-lateral-movement
description: Run the Redstrike AD lateral-movement hunt — PtH/PtT/relay to another in-scope host with a recovered credential + a benign command to prove reach — then gate and hand off to the ad-lateral-movement-verify reviewer agent. High-impact, approval-gated.
---

Run the Redstrike **ad-lateral-movement** methodology (canonical spec: `skills/ad-lateral-movement/`). AD, high-impact.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Authenticate + run a BENIGN command (`whoami`) to prove reach — **no** destructive actions, data theft, persistence/backdoors, or disruptive coercion on prod. In-scope hosts only. Remove exec artifacts (`cleanup.md`).
2. **Execute:** follow `skills/ad-lateral-movement/SKILL.md`; consume `<engagement>/ad-context/ad_context.json` + credentials recovered by `redstrike-ad-kerberos`/`ad-acl-abuse`/`ad-adcs`; work `skills/ad-lateral-movement/checklist.md`; use `skills/ad-context/refs/`. Write outputs to `<engagement>/ad-lateral-movement/`. On a landed host → `redstrike-windows-privesc`.
3. **Coverage:** copy your filled checklist into `<engagement>/ad-lateral-movement/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ad-lateral-movement --out <engagement>/ad-lateral-movement` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ad-lateral-movement-verify` subagent on `<engagement>/ad-lateral-movement`. Only `accepted` findings go to reporting.
