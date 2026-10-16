# Mobile attack reference (Android + iOS)
# Approval-gated. AUTHORIZED app + test device only. Benign proof. REDACT all secrets/keys/tokens in artifacts.
# Map findings to OWASP MASVS controls (STORAGE / CRYPTO / AUTH / NETWORK / PLATFORM / CODE / RESILIENCE).

## Static analysis (first pass)
```
# Android:
unzip app.apk -d app_src                         # inspect resources, assets, lib/
apktool d app.apk -o app_apktool                 # smali + decoded AndroidManifest.xml
jadx -d app_jadx app.apk                         # decompile to Java
# iOS (.ipa is a zip): Payload/<App>.app/ -> Info.plist, embedded.mobileprovision, Frameworks/
# Automated triage: MobSF (static) surfaces manifest flags, secrets, insecure API usage.
```
Read in the manifest/Info.plist: exported components, URL schemes/deeplinks, `android:debuggable`,
`android:allowBackup`, cleartext-traffic flag / ATS exceptions, requested permissions, min-SDK.

## Insecure local storage  (MASVS-STORAGE)
- Android: `shared_prefs/*.xml`, `databases/*.sqlite`, `files/`, external storage — look for tokens,
  passwords, PII, keys stored in plaintext or with a hardcoded/derivable key.
- iOS: `NSUserDefaults` plist, app `Documents/`/`Library/` sqlite, Keychain items with weak
  accessibility (`kSecAttrAccessibleAlways`). Check Keychain entries aren't world-persistent.
```
# Live inspection on a test device:
objection -g <pkg> explore                        # then: android keystore list / ios keychain dump
adb shell run-as <pkg> cat shared_prefs/<file>.xml
```
Benign proof: read ONE stored secret (redact it to a fingerprint). Do not dump the whole store.

## Traffic interception + TLS / cert-pinning bypass  (MASVS-NETWORK)
```
# 1. Route app traffic through Burp (install CA on the test device / emulator).
# 2. If traffic fails (pinned), bypass pinning with instrumentation:
objection -g <pkg> explore -s "android sslpinning disable"      # Android
objection -g <bundle> explore -s "ios sslpinning disable"       # iOS
frida -U -f <pkg> -l pinning_bypass.js --no-pause               # custom hook on the pinning API
```
Benign proof: show ONE request/response flowing through the proxy after the bypass; confirm whether
cleartext or weak TLS is also accepted. Note endpoints that transmit credentials/PII.

## Exported components  (MASVS-PLATFORM)
Activities / services / broadcast receivers / content providers marked exported (or with an intent-filter
and no permission) are reachable by any app on the device.
```
# Enumerate from the manifest (exported="true" or implicit via intent-filter, no signature permission).
adb shell am start -n <pkg>/<activity> --es key value          # launch an exported activity
adb shell am startservice -n <pkg>/<service>
adb shell am broadcast -a <action> --es key value              # fire into an exported receiver
content query --uri content://<authority>/<path>               # query an exported provider (SQLi/path-traversal?)
```
Benign proof: invoke ONE exported component to trigger a benign, observable effect (a screen that should
require auth, a provider row, an action performed without permission).

## Insecure deeplinks / URL schemes  (MASVS-PLATFORM)
- Custom scheme (`myapp://`) or App Links / Universal Links that pass data into sensitive flows without
  validation → parameter injection, auth-context confusion, WebView loading of an attacker URL.
```
adb shell am start -a android.intent.action.VIEW -d "myapp://path?next=https://attacker.example"
# iOS: open the scheme from Safari / a note to observe handling.
```
Benign proof: show a deeplink reaching a sensitive handler / loading an attacker-chosen value.

## Hardcoded secrets / keys  (MASVS-CRYPTO / CODE)
Grep decompiled source + resources for API keys, cloud creds, signing keys, encryption keys, backend
URLs, and secrets in `strings.xml`/`BuildConfig`/`Info.plist`. Validate impact of a live key out-of-band
and redact it. A key that only unlocks client-side obfuscation is lower severity than a live backend cred.

## Insecure WebView  (MASVS-PLATFORM)
- `setJavaScriptEnabled(true)` + `addJavascriptInterface(obj, "name")` exposes native methods to page JS —
  an attacker-controlled page (via deeplink/redirect/XSS) can call them.
- `setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs` + loading `file://` → local file read.
- Loading mixed/attacker content over http, or ignoring TLS errors (`onReceivedSslError` proceed).
Benign proof: reach a JS-bridge method or read a benign local file from an attacker-influenced page.

## Root / jailbreak-detection bypass  (MASVS-RESILIENCE)
If root/jailbreak checks gate functionality, hook them to show the control is bypassable:
```
objection -g <pkg> explore -s "android root disable"
frida -U -f <pkg> -l rootbypass.js --no-pause           # hook the detection method -> return false
```
This is a resilience (defence-in-depth) finding — rate honestly; it is not by itself a data-access issue.

## Backup + clipboard leakage  (MASVS-STORAGE)
- `android:allowBackup="true"` → `adb backup` may extract app data on older devices.
- Sensitive fields copied to the system clipboard (no `FLAG_SECURE` / no clipboard clearing) → readable by
  other apps. Screenshots of sensitive screens (no secure flag) persist in recents.

## Reporting
Each finding: platform, MASVS control, the component/path/endpoint, the vector, the benign proof (redacted),
attacker preconditions (rooted device? co-located app? physical access?), and remediation. Never ship the
repackaged/instrumented build or raw user data in artifacts.
