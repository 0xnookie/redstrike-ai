# Wireless Assessment Agent

> ATOMIC agent — Wi-Fi + short-range RF security against AUTHORIZED networks/devices: WPA2-PSK handshake crack, WPA3-SAE downgrade, WPS pixie-dust, evil-twin/rogue-AP, WPA-Enterprise EAP credential capture, BLE/Zigbee overview.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (RF assessment; deauth prod-forbidden). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** survey in-scope SSIDs/BSSIDs + clients → select a vector (PSK handshake capture, WPS, evil-twin, Enterprise EAP) → capture/stand up the test → offline-crack or capture credentials on an AUTHORIZED test network → confirm benignly → rate → emit → review → verify.
- **TOOLS:** aircrack-ng suite (`airmon-ng`/`airodump-ng`/`aireplay-ng`/`aircrack-ng`), `hcxtools` (`hcxdumptool`) + `hashcat`, `bettercap`, `reaver`/`bully`, `hostapd`/`wifiphisher`/`hostapd-wpe`, `refs/wireless_attacks.md`.
- **GOAL:** Confirm a wireless security issue — a crackable WPA2-PSK, a WPS pixie-dust-recoverable PIN, a client that associates to an evil-twin and submits credentials, or WPA-Enterprise creds captured via a rogue EAP endpoint — on an AUTHORIZED test network, with a benign proof. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `wifi_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = in-scope SSIDs/BSSIDs + a test SSID/test client + `scope.yaml` (RF scope, locations). `refs/` = `wireless_attacks.md`. Chains FROM physical/on-site access; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic; WPA2/WPA3/WPS/Enterprise/evil-twin/short-range variants in refs).

## Goal
Prove a wireless issue benignly on an authorized network (PSK/WPS/evil-twin/Enterprise). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The in-scope network/device + the reachable vector (weak PSK, WPS enabled, no client isolation / PEAP without server-cert validation, WPA3 transition-mode downgrade)
- The vector + what it yields (recovered PSK, recovered WPS PIN, captured portal/EAP credentials, downgrade to WPA2)
- A benign proof on an AUTHORIZED target: capture + offline-crack a TEST SSID handshake, OR stand up an evil-twin for a TEST client and capture a benign test credential — **never** deauth against production

## Steps  (action · tool · output)
1. Survey in-scope SSIDs/BSSIDs/clients (passive) + confirm RF scope · `airodump-ng`/`bettercap` · (into tests)
2. WPA2-PSK: capture handshake (passive, or a scoped/approved client re-assoc) → offline crack · `hcxdumptool`→`hashcat -m 22000` / `aircrack-ng` · `wifi_tests.jsonl`
3. WPS (if enabled): pixie-dust PIN recovery on an AUTHORIZED AP · `reaver`/`bully` · `wifi_tests.jsonl`
4. WPA3-SAE: test transition-mode/downgrade to WPA2 + note SAE handshake weaknesses · aircrack-ng suite · `wifi_tests.jsonl`
5. Evil-twin / rogue-AP: stand up a TEST AP + captive portal for a TEST client; capture a benign test credential · `hostapd`/`wifiphisher` · `poc/<id>/`
6. WPA-Enterprise: rogue EAP endpoint captures the client challenge/response (benign test identity) → offline crack · `hostapd-wpe`→`hashcat` · `wifi_tests.jsonl`
7. Confirm ONE issue benignly + rate (CVSS) · synth · `poc/<id>/`, `findings.json`
8. Emit report · synth · `report.md` · 9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- aircrack-ng suite, `hcxtools`/`hcxdumptool` + `hashcat`, `bettercap`, `reaver`/`bully`, `hostapd`/`wifiphisher`/`hostapd-wpe`, `refs/wireless_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- In-scope SSIDs/BSSIDs, a test SSID + test client, RF scope/locations, `scope.yaml`

## Outputs
`wifi_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** passive survey + handshake/PIN capture on authorized targets.
- **Phase 2 (target-specific):** offline crack / evil-twin / Enterprise credential capture + rating (approval-gated).

## Safety
Approval-gated (RF assessment). **No deauth / forced disassociation against production** — handshake capture
is passive or uses an approved test client only; cracking is OFFLINE. Evil-twin and captive-portal/EAP
capture target a TEST client with benign test credentials, time-boxed, and the rogue AP is torn down after.
**Redact** recovered PSKs/PINs/credentials to a fingerprint. In-scope SSIDs/locations only; do not interfere
with neighbouring (out-of-scope) networks; audit-log.
