---
name: redstrike-mobile
description: Run the Redstrike mobile application hunt (executor) — Android/iOS static + dynamic analysis of an AUTHORIZED build: insecure local storage, traffic interception + TLS/cert-pinning bypass, exported components, insecure deeplinks, hardcoded secrets, unsafe WebView, root/jailbreak-detection bypass — mapped to OWASP MASVS and confirmed with a benign proof, secrets redacted — then gate and hand off to the mobile-verify reviewer agent. Approval-gated.
---

Run the Redstrike **mobile** methodology (canonical spec: `skills/mobile/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (authorized app + test device); in-scope app/bundle IDs only; test accounts only; benign proof; REDACT all secrets/keys/tokens to a fingerprint; never distribute a repackaged build.
2. **Execute:** follow `skills/mobile/SKILL.md`; consume the authorized package (APK/IPA) + a test device/emulator; work `skills/mobile/checklist.md`; use `skills/mobile/refs/`. Write outputs to `<engagement>/mobile/`.
3. **Coverage:** copy your filled checklist into `<engagement>/mobile/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/mobile --out <engagement>/mobile` → fix + re-run until exit 0.
5. **Reviewer:** launch the `mobile-verify` subagent on `<engagement>/mobile`. Only `accepted` findings go to reporting.
