---
name: redstrike-cloud
description: Run the Redstrike cloud exploitation hunt (executor) — AWS/Azure/GCP metadata-credential theft (SSRF→IMDS), identity + permission enumeration, IAM privesc and public-storage exposure, confirmed with a benign identity call and creds redacted — then gate and hand off to the cloud-verify reviewer agent. Approval-gated.
---

Run the Redstrike **cloud** methodology (canonical spec: `skills/cloud/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (real cloud account); in-scope account IDs only; read-only + benign proof; REDACT all creds/tokens to a fingerprint.
2. **Execute:** follow `skills/cloud/SKILL.md`; consume an SSRF-to-metadata (from `ssrf-cloud`) or given keys; work `skills/cloud/checklist.md`; use `skills/cloud/refs/`. Write outputs to `<engagement>/cloud/`.
3. **Coverage:** copy your filled checklist into `<engagement>/cloud/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/cloud --out <engagement>/cloud` → fix + re-run until exit 0.
5. **Reviewer:** launch the `cloud-verify` subagent on `<engagement>/cloud`. Only `accepted` findings go to reporting.
