# IoT / Embedded — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the IoT gauntlet. Confirmed = a concrete embedded weakness proven benignly on the
AUTHORIZED device/image (a default/hardcoded credential or key recovered from the extracted filesystem, a
reachable debug console, an unsigned/forgeable update, or an exposed service), secrets redacted. Re-run the
benign proof where repeatable.

## IoT false-positive gauntlet (base check #3)
- [ ] **The weakness is demonstrated, not inferred.** The PoC shows the extracted filesystem and the actual
      recovered secret (a `passwd`/`shadow` hash cracked, a hardcoded key in a config/binary, a client cert),
      a console banner/prompt reached over UART/JTAG, or the update signature check shown to be absent —
      not "the firmware probably contains a key".
- [ ] **The secret is real + usable, not a build artefact.** A recovered credential/key maps to a real
      function (device login, OTA signing, an API) — distinguished from a sample/placeholder/test fixture.
- [ ] **Benign + redacted.** No device bricked, no modified firmware flashed, no persistent change, no
      production/field device touched; every recovered credential/key/cert is REDACTED to a fingerprint.
- [ ] **Severity matches reach.** Shared default root credential across the fleet / OTA signing key / remote
      pre-auth exposed service → High/Critical; a local-only debug interface needing physical access → Medium.
- [ ] **In scope** (device models/images) + approval.

## CVSS integrity
Rate from reach and preconditions — is the secret shared across the fleet (remote impact) or unique per
device; does exploitation need physical access, the dumped image, or network reach? Not merely that a
string was found.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "iot-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["binwalk extracted the squashfs; /etc/shadow root hash cracked offline to a default password (redacted); same across the model; in-scope image"],
  "scope_ok": true, "notes": "secret redacted to fingerprint; no device bricked/flashed; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
