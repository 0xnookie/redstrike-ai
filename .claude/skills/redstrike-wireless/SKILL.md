---
name: redstrike-wireless
description: Run the Redstrike wireless assessment hunt (executor) — Wi-Fi + short-range RF against AUTHORIZED networks: WPA2-PSK handshake capture + offline crack (hcxdumptool → hashcat -m 22000), WPA3-SAE transition/downgrade, WPS pixie-dust, evil-twin/rogue-AP + captive-portal capture, WPA-Enterprise EAP credential capture — confirmed benignly with NO deauth against production and secrets redacted — then gate and hand off to the wireless-verify reviewer agent. Approval-gated.
---

Run the Redstrike **wireless** methodology (canonical spec: `skills/wireless/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (RF assessment); in-scope SSIDs/locations only; **no deauth against production**; cracking is OFFLINE; evil-twin/EAP capture targets a TEST client with benign test creds and is torn down after; REDACT recovered PSKs/PINs/credentials to a fingerprint.
2. **Execute:** follow `skills/wireless/SKILL.md`; consume in-scope SSIDs/BSSIDs + a test SSID/test client; work `skills/wireless/checklist.md`; use `skills/wireless/refs/`. Write outputs to `<engagement>/wireless/`.
3. **Coverage:** copy your filled checklist into `<engagement>/wireless/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/wireless --out <engagement>/wireless` → fix + re-run until exit 0.
5. **Reviewer:** launch the `wireless-verify` subagent on `<engagement>/wireless`. Only `accepted` findings go to reporting.
