---
name: redstrike-credential-access
description: Run the Redstrike credential-access hunt (post-exploitation) — authorized online guessing (rate-limited, lockout-aware), offline hash cracking, and credential-store review on a landed host; confirm ONE weak/recoverable credential benignly with every secret redacted — then gate and hand off to the credential-access-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **credential-access** methodology (canonical spec: `skills/credential-access/`). Post-exploitation.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Crack OFFLINE only; online guessing is rate-limited + lockout-aware (never lock out real users). **REDACT** every secret to a fingerprint; delete collected hash material (`cleanup.md`); don't reuse recovered real credentials beyond the single proof without approval. In-scope only.
2. **Execute:** follow `skills/credential-access/SKILL.md`; work `skills/credential-access/checklist.md`; use `skills/credential-access/refs/`. Write outputs to `<engagement>/credential-access/`.
3. **Coverage:** copy your filled checklist into `<engagement>/credential-access/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/credential-access --out <engagement>/credential-access` → fix + re-run until exit 0.
5. **Reviewer:** launch the `credential-access-verify` subagent on `<engagement>/credential-access`. Only `accepted` findings go to reporting.
