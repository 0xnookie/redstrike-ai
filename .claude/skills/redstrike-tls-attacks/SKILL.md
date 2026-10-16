---
name: redstrike-tls-attacks
description: Run the Redstrike tls-attacks hunt (executor) — TLS/SSL protocol + cipher downgrade, weak config (SSLv3/TLS1.0-1.1, RC4/EXPORT/DES), certificate flaws, named issues (Heartbleed/POODLE/ROBOT/BEAST/CCS/Raccoon), STARTTLS stripping and missing HSTS, confirmed by a benign read-only scan or a bounded controlled check on an authorized host — then gate and hand off to the tls-attacks-verify reviewer agent. Approval-gated for active probes.
---

Run the Redstrike **tls-attacks** methodology (canonical spec: `skills/tls-attacks/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. The scan is read-only; **approval required** for active vulnerability probes (Heartbleed/ROBOT/CCS/…) — a SMALL controlled over-read only (never a memory-exfil loop), bounded handshakes, no DoS, no credential capture; redact any returned bytes; in-scope host:port only.
2. **Execute:** follow `skills/tls-attacks/SKILL.md`; enumerate endpoints, scan protocols/ciphers/cert, check named issues + STARTTLS/HSTS, confirm one weakness benignly; work `skills/tls-attacks/checklist.md`; use `skills/tls-attacks/refs/`. Write outputs to `<engagement>/tls-attacks/`.
3. **Coverage:** copy your filled checklist into `<engagement>/tls-attacks/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/tls-attacks --out <engagement>/tls-attacks` → fix + re-run until exit 0.
5. **Reviewer:** launch the `tls-attacks-verify` subagent on `<engagement>/tls-attacks`. Only `accepted` findings go to reporting.
