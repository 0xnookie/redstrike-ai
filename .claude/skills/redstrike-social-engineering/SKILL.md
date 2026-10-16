---
name: redstrike-social-engineering
description: Run the Redstrike social-engineering hunt (executor) — AUTHORIZED phishing + pretext simulation (gophish campaign, landing/credential-harvest page, tracking; link/attachment/OAuth-consent delivery; vishing/smishing; OSINT-driven targeting) measuring human-layer controls via click/submit/report metrics — ONLY with explicit written authorization naming the target population, no real malware, benign test submissions, aggregate findings with no named-person blame — then gate and hand off to the social-engineering-verify reviewer agent. Heavily authorization-gated.
---

Run the Redstrike **social-engineering** methodology (canonical spec: `skills/social-engineering/`).

1. **Scope + authorization (heaviest gate):** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Proceed ONLY with explicit **written authorization that names the target population**; authorized sender domains + window only; no out-of-scope individuals / third parties / non-consenting people; **no real malware**; the harvest page must NEVER store real passwords (hash+discard / accept-and-redirect); findings are process/control gaps + aggregate metrics, never named-person blame.
2. **Execute:** follow `skills/social-engineering/SKILL.md`; consume the written authorization + scoped `osint`; work `skills/social-engineering/checklist.md`; use `skills/social-engineering/refs/`. Write outputs to `<engagement>/social-engineering/`.
3. **Coverage:** copy your filled checklist into `<engagement>/social-engineering/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/social-engineering --out <engagement>/social-engineering` → fix + re-run until exit 0.
5. **Reviewer:** launch the `social-engineering-verify` subagent on `<engagement>/social-engineering`. Only `accepted` findings go to reporting. Tear down the campaign + harvest page after.
