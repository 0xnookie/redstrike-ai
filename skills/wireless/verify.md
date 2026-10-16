# Wireless Assessment — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the wireless gauntlet. Confirmed = a real wireless weakness proven benignly on an
AUTHORIZED network/device (a cracked TEST-SSID handshake, a recovered WPS PIN, a TEST client that associated
to an evil-twin and submitted a benign credential, or captured Enterprise challenge/response). Re-run the
benign proof where repeatable.

## Wireless false-positive gauntlet (base check #3)
- [ ] **The result is demonstrated, not theoretical.** A WPA2 handshake was captured AND cracked offline
      (PSK recovered), a WPS PIN was recovered, a client associated to the rogue AP and a benign credential
      was captured, or an EAP challenge/response was captured — not just "WPS looks enabled" or "weak-ish SSID".
- [ ] **No production disruption occurred.** Handshake capture was passive or used an approved test client;
      there was **no deauth/disassociation against production**; the evil-twin/EAP endpoint targeted a TEST
      client and was torn down. Confirm the method did not knock real users offline.
- [ ] **Benign + redacted.** Cracking was offline; captured credentials are benign test creds; recovered
      PSK/PIN/credentials are REDACTED to a fingerprint in artifacts.
- [ ] **Severity matches reach.** Recovered production PSK / Enterprise creds / full client-credential
      capture → High/Critical; WPS enabled or transition-mode downgrade feasibility → Medium.
- [ ] **In scope** (SSIDs/locations) + approval; no interference with out-of-scope neighbouring networks.

## CVSS integrity
Rate from what the recovered secret unlocks (network access, lateral reach, identity reuse) and the attacker
preconditions (RF proximity, a willing/approved test client), not merely that a handshake was captured.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "wireless-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["hcxdumptool captured the 4-way handshake for TEST-SSID; hashcat -m 22000 recovered the PSK offline (redacted); no deauth against prod; in-scope SSID"],
  "scope_ok": true, "notes": "offline crack; PSK redacted to fingerprint; no production disruption; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
