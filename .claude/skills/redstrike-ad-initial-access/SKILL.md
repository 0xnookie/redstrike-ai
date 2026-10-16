---
name: redstrike-ad-initial-access
description: Run the Redstrike AD initial-access hunt (post-exploitation) — unauthenticated to a first valid domain credential via passive name-resolution capture, authentication coercion, policy-first password spraying, and anonymous enumeration; confirm one credential benignly (offline crack / benign login), secrets redacted — then gate and hand off to the ad-initial-access-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **ad-initial-access** methodology (canonical spec: `skills/ad-initial-access/`). Post-exploitation / internal.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Prefer PASSIVE capture; poisoning is time-boxed + stopped; spraying is policy-first + lockout-aware (one password, spaced — never lock accounts); crack OFFLINE; **redact** captured hashes/credentials; coercion only toward an in-scope listener, non-disruptive. In-scope network only.
2. **Execute:** follow `skills/ad-initial-access/SKILL.md`; work `skills/ad-initial-access/checklist.md`; use `skills/ad-initial-access/refs/`. Write outputs to `<engagement>/ad-initial-access/`. Hand the first credential to `redstrike-ad-context`.
3. **Coverage:** copy your filled checklist into `<engagement>/ad-initial-access/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ad-initial-access --out <engagement>/ad-initial-access` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ad-initial-access-verify` subagent on `<engagement>/ad-initial-access`. Only `accepted` findings go to reporting.
