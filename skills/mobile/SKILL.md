# Mobile Application Agent

> ATOMIC agent — mobile app security (Android + iOS) against an AUTHORIZED build: local storage, traffic/TLS pinning, exported components, deeplinks, hardcoded secrets, WebView, root/jailbreak checks.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (authorized app + test device). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest the authorized package (APK/IPA) → static analysis (decompile, manifest, components, secrets, WebView config) → set up an instrumented test device → dynamic analysis (local storage, traffic + pinning bypass, exported-component invocation, deeplinks, WebView, root/jailbreak checks) → confirm one issue benignly → rate → emit → review → verify.
- **TOOLS:** `jadx`/`apktool` (Android static), `frida`/`objection` (instrumentation + pinning bypass), `MobSF` (automated scan), Burp (proxy), `refs/mobile_attacks.md`.
- **GOAL:** Confirm a mobile security issue — insecure local storage, interceptable/unpinned traffic, an abusable exported component or deeplink, a hardcoded secret/key, an unsafe WebView, or a bypassable root/jailbreak check — mapped to OWASP MASVS, with a benign proof on the AUTHORIZED build. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `mobile_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = the authorized app package (APK/IPA) + a test device/emulator + `scope.yaml` (app IDs / bundle IDs in scope). `refs/` = `mobile_attacks.md`. Chains FROM a provided build; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic; Android + iOS variants in refs).

## Goal
Prove a mobile app issue benignly on the authorized build (storage/traffic/components/secrets/WebView). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The platform + reachable weakness (plaintext local store, no/weak cert-pinning, exported activity/service/receiver/provider, insecure deeplink/URL scheme, hardcoded key, JS-bridge/file-access WebView, bypassable root/jailbreak detection, backup/clipboard leakage)
- The vector + what it yields (readable secret, intercepted traffic, an invoked privileged action, a leaked token)
- A benign proof on the AUTHORIZED app: read ONE stored secret, OR view traffic after a pinning bypass, OR invoke an exported component with a benign effect — NOT bulk user-data exfiltration

## Steps  (action · tool · output)
1. Ingest authorized build + fingerprint platform/framework (native / cross-platform) · unzip/`jadx`/`apktool` · (into tests)
2. Static: manifest + exported components + deeplinks/URL schemes + secrets/keys + WebView config · `jadx`/`apktool`/`MobSF` · `mobile_tests.jsonl`
3. Dynamic setup: instrument a test device (`frida`/`objection`), proxy through Burp · instrumentation · `logs/`
4. Local storage review (SharedPrefs / plist / Keychain / sqlite) for secrets/PII · `objection`/adb · `mobile_tests.jsonl`
5. Traffic + TLS: intercept; if pinned, bypass pinning (`objection`/Frida hook) to view request/response · Burp/Frida · `mobile_tests.jsonl`
6. Exported-component + deeplink abuse (intent / URL-scheme invocation) + WebView (JS bridge / file access) · adb/Frida · `mobile_tests.jsonl`
7. Root/jailbreak-detection bypass (if it gates functionality) + backup/clipboard leakage · Frida · `mobile_tests.jsonl`
8. Confirm ONE issue benignly + rate (CVSS) + write finding (REDACT secrets) · synth · `poc/<id>/`, `findings.json`
9. Emit report · synth · `report.md` · 10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- `jadx`/`apktool`, `frida`/`objection`, `MobSF`, Burp, `refs/mobile_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- Authorized app package (APK/IPA), test device/emulator, in-scope app/bundle IDs, `scope.yaml`

## Outputs
`mobile_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** static analysis + instrumented-device setup.
- **Phase 2 (target-specific):** dynamic storage/traffic/component/WebView proof + rating (approval-gated).

## Safety
Approval-gated (authorized app + test device only). Benign proof on the AUTHORIZED build — read ONE marker
secret / view traffic / invoke one component; **no** bulk user-data exfiltration, no modification of other
users' data, no distribution of a repackaged build. **Redact** every recovered secret/key/token to a
fingerprint in artifacts. In-scope app/bundle IDs only; test accounts only; audit-log.
