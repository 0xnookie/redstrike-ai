---
name: redstrike-iot
description: Run the Redstrike IoT/embedded hunt (executor) — firmware acquisition + extraction (binwalk/unblob/firmware-mod-kit), filesystem/entropy analysis, hardcoded/default creds + keys, insecure update mechanisms, hardware interfaces (UART/JTAG/SWD console, SPI-flash dump with flashrom), embedded-binary analysis (Ghidra), and exposed services — on an AUTHORIZED device/image, confirmed with a benign proof and secrets redacted — then gate and hand off to the iot-verify reviewer agent. Approval-gated.
---

Run the Redstrike **iot** methodology (canonical spec: `skills/iot/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (authorized device/image); in-scope models/images only; benign proof; **no bricking, no flashing modified firmware, no production/field device**; REDACT all recovered credentials/keys/certs to a fingerprint.
2. **Execute:** follow `skills/iot/SKILL.md`; consume the authorized firmware image (or device + hardware access); work `skills/iot/checklist.md`; use `skills/iot/refs/`. Write outputs to `<engagement>/iot/`.
3. **Coverage:** copy your filled checklist into `<engagement>/iot/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/iot --out <engagement>/iot` → fix + re-run until exit 0.
5. **Reviewer:** launch the `iot-verify` subagent on `<engagement>/iot`. Only `accepted` findings go to reporting.
