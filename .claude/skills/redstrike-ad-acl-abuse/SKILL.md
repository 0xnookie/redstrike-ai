---
name: redstrike-ad-acl-abuse
description: Run the Redstrike AD ACL-abuse hunt — exercise ACL edges (ForceChangePassword / shadow creds / WriteDacl / AddMember / single-account DCSync) on test principals, always reverting — then gate and hand off to the ad-acl-abuse-verify reviewer agent. High-impact, approval-gated.
---

Run the Redstrike **ad-acl-abuse** methodology (canonical spec: `skills/ad-acl-abuse/`). AD, high-impact.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Exercise edges against TEST principals you can revert; **always revert** (passwords/DACLs/memberships/shadow creds) — tracked in `cleanup.md`. DCSync a SINGLE test account to prove the right, **never** the whole domain / krbtgt.
2. **Execute:** follow `skills/ad-acl-abuse/SKILL.md`; consume `<engagement>/ad-context/ad_context.json` (`acl_edges` + foothold); work `skills/ad-acl-abuse/checklist.md`; use `skills/ad-context/refs/`. Write outputs to `<engagement>/ad-acl-abuse/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ad-acl-abuse/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ad-acl-abuse --out <engagement>/ad-acl-abuse` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ad-acl-abuse-verify` subagent on `<engagement>/ad-acl-abuse`. Only `accepted` findings go to reporting.
