# Mobile Application — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Authorized package (APK/IPA) ingested + platform/framework fingerprinted
- [ ] Approval obtained (RoE — authorized app + test device) + in-scope app/bundle IDs confirmed

## Test (scope-gated, benign, test device)
- [ ] Static: manifest, exported components, deeplinks/URL schemes, secrets, WebView config reviewed
- [ ] Local storage inspected (SharedPrefs / plist / Keychain / sqlite) — secrets REDACTED in artifacts
- [ ] Traffic intercepted; cert-pinning bypass attempted where present
- [ ] Exported-component / deeplink invocation tested (benign effect)
- [ ] WebView (JS bridge / file access) + root/jailbreak-detection bypass + backup/clipboard leakage checked
- [ ] One issue confirmed benignly (read a marker secret / view traffic / invoke a component)
- [ ] CVSS rated (mapped to OWASP MASVS)

## Emit
- [ ] findings.json (schema-valid, secrets redacted)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
