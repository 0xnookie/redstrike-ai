# Mobile Application — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the mobile gauntlet. Confirmed = a concrete mobile weakness proven benignly on the
AUTHORIZED build (a recovered secret / intercepted traffic after pinning bypass / an invoked exported
component), mapped to OWASP MASVS, secrets redacted. Re-run the benign proof.

## Mobile false-positive gauntlet (base check #3)
- [ ] **The weakness is demonstrated, not inferred.** The PoC shows the actual effect — a secret read from
      SharedPrefs/plist/Keychain/sqlite, a request/response captured after a pinning bypass, an exported
      component/deeplink invoked with a benign effect, or a WebView bridge reached — not just "the manifest
      exports this" or "MobSF flagged it".
- [ ] **It's an app weakness, not test-harness artefact.** The effect comes from the shipped app logic
      (exported surface, storage, WebView, missing/weak pinning), not from a rooted-device convenience or a
      debug build the user wouldn't ship.
- [ ] **Benign + redacted.** One marker proof only — no bulk user-data pull, no other-user data touched,
      no repackaged build distributed; every secret/key/token is REDACTED to a fingerprint in artifacts.
- [ ] **Severity matches reach.** Hardcoded high-value key / full traffic interception / exported component
      that performs a privileged action → High/Critical; local-only info leak needing device access → Low/Medium.
- [ ] **In scope** (app/bundle IDs) + approval; test accounts only.

## CVSS integrity
Rate from the real blast radius (attacker preconditions: does it need a rooted/jailbroken device, physical
access, or a malicious co-located app?), not merely that a check was bypassable. Map to the relevant OWASP MASVS control.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "mobile-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["objection bypassed cert-pinning; Burp captured the /api/login request+response over TLS; token redacted; MASVS-NETWORK; reproduced on test device"],
  "scope_ok": true, "notes": "secrets redacted to fingerprint; benign proof on authorized build; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
