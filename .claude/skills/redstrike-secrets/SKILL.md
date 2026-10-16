---
name: redstrike-secrets
description: Run the Redstrike secrets-validation hunt (executor) — validate exposed secrets from js-analysis as real/live/impactful, redacted — then gate and hand off to the secrets-verify reviewer agent.
---

Run the Redstrike **secrets** methodology (canonical spec: `skills/secrets/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Validating a secret USES someone's credential — do the MINIMUM benign, read-only probe to prove liveness, only where authorized; never access/exfiltrate/modify.
2. **Execute:** follow `skills/secrets/SKILL.md`; ingest `skills/js-analysis/secrets.json` (+ `refs/secret_regexes.yaml`); work `skills/secrets/checklist.md`. Write outputs to `<engagement>/secrets/`. Store REDACTED fingerprints (last 4 + hash) — never full secrets in artifacts.
3. **Coverage:** copy your filled checklist into `<engagement>/secrets/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/secrets --out <engagement>/secrets` → fix + re-run until exit 0.
5. **Reviewer:** launch the `secrets-verify` subagent on `<engagement>/secrets`. Only `accepted` findings go to reporting.
