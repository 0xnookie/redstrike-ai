---
name: redstrike-ad-adcs
description: Run the Redstrike AD Certificate Services hunt (ESC1-8) — abuse a vulnerable template/CA to issue + authenticate a cert as a test principal, then revoke it — then gate and hand off to the ad-adcs-verify reviewer agent. High-impact, approval-gated.
---

Run the Redstrike **ad-adcs** methodology (canonical spec: `skills/ad-adcs/`). AD, high-impact.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Request a cert for a TEST privileged principal to PROVE the ESC; authenticate to confirm; then **revoke** the certificate (`cleanup.md`). Do NOT mint a DA cert and persist. ESC8 coercion needs approval (non-disruptive).
2. **Execute:** follow `skills/ad-adcs/SKILL.md`; consume `<engagement>/ad-context/ad_context.json` (`adcs` + foothold); work `skills/ad-adcs/checklist.md`; use `skills/ad-context/refs/`. Write outputs to `<engagement>/ad-adcs/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ad-adcs/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ad-adcs --out <engagement>/ad-adcs` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ad-adcs-verify` subagent on `<engagement>/ad-adcs`. Only `accepted` findings go to reporting.
