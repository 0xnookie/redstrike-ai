# Social-engineering methodology (authorized phishing + pretext simulation)
# HEAVIEST authorization gate. Proceed ONLY with explicit WRITTEN authorization that NAMES the target
# population. No out-of-scope individuals, third parties, or non-consenting people. No real malware.
# Findings = process/control gaps + AGGREGATE metrics, never named-person blame. Teardown after.

## Authorization preconditions (do these FIRST)
- Signed written authorization on file that names the **target population** (group/department/role), the
  **authorized sender domains**, the **time window**, and the **permitted delivery options**.
- A defined point of contact + abort/kill-switch, and a rule for handling any sensitive data captured.
- Confirm the population excludes anyone out of scope; never target a real customer/third party/individual
  outside the authorization. If the scope is ambiguous, STOP and re-confirm.

## Campaign setup (gophish)
- **Sending profile:** an authorized sender domain + mail server; warm/verify deliverability within scope.
- **Landing / credential-harvest page:** clone or build the lure page. The page must **never store real
  passwords** — capture only that a submission happened (hash+discard, or accept-and-redirect to an
  awareness/training page). Record the event, not the secret.
- **Tracking:** per-recipient tokens for open/click/submit; a tracking pixel for opens; unique landing URLs.
- **Campaign:** map the template + landing page + sending profile + the authorized recipient group; schedule
  within the window; keep an audit trail of every send.

## Pretext design
- Build a plausible, in-scope pretext aligned to the control under test (IT notice, benefits/HR, delivery,
  shared-document). Keep it benign and non-defamatory; avoid high-distress themes (e.g. fake terminations,
  real-incident impersonation) unless explicitly authorized.
- Define the success signal you are measuring (click, credential submit, attachment open, consent grant).

## Payload delivery options (choose an APPROVED one)
- **Tracked link:** recipient clicks → tracked → lands on the harvest/awareness page. Lowest risk.
- **Attachment:** a BENIGN document that only beacons on open (macro-free tracking / a tracked remote
  resource). **No real malware, no working exploit, no live payload.**
- **OAuth-consent:** an app-consent prompt measuring whether users grant third-party access (consent
  phishing). Register an in-scope benign app; measure consent grants; request minimal scopes; revoke after.

## Vishing / smishing methodology (if in scope)
- Vishing: a scripted, benign pretext call to the authorized population measuring whether the caller can
  elicit a scoped action (e.g. visiting the awareness page) — no real secrets collected.
- Smishing: a tracked SMS lure to authorized, consented numbers only. Same no-real-malware / no-real-secret
  rules. Honor local regulations on SMS/calls.

## OSINT-driven targeting (scoped)
Use only scoped OSINT (from the `osint` feeder) to tailor the pretext to the authorized population — roles,
tooling, public org structure. Do NOT expand the recipient set beyond the authorization or profile
individuals for blame.

## Metrics (what you actually report)
- Aggregate rates: **sent → delivered → opened → clicked → submitted → reported**, plus consent-grant rate
  for OAuth tests. Time-to-first-report and % who used the reporting path are key control signals.
- Control gaps surfaced: missing/slow reporting path, high credential-submit rate, weak mail filtering,
  OAuth-consent allowed, no MFA on the targeted flow.

## Reporting framing
- Report **process/control gaps + aggregate metrics**. Do NOT name or shame individuals; do not include a
  per-person leaderboard. Recommendations target controls + training, not discipline.
- Redact any sensitive data incidentally captured. Confirm the campaign, harvest page, and any registered
  consent app were torn down / revoked.

---

## Extended arsenal — lookalike domain generation (homograph / IDN / combosquatting)

Register look-alikes ONLY within the authorized sender-domain list; a domain outside that list is out of
scope. Model these permutation classes (and teach the defender to monitor + block them):

| Class | Example vs `example.com` | Note |
|---|---|---|
| Homoglyph / IDN | Cyrillic `а` → `exаmple.com` | on the wire as punycode `xn--...` |
| Typo / transposition | `exmaple.com`, `exampel.com` | adjacent-key + char swap |
| Omission / repetition | `exaple.com`, `exxample.com` | dropped / doubled char |
| TLD swap | `example.net`, `example.co` | new / ccTLD variant |
| Combosquat | `example-login.com`, `secure-example.com` | keyword glued to the brand |
| Bitsquat | single-bit flip of a label char | DNS cache / memory bit errors |
| Subdomain insert | `example.com.evil-host.com` | brand sits in the left label |

```
# Generate + triage candidates (do NOT register anything outside the authorized list)
dnstwist --registered example.com                        # live permutations w/ resolved A/MX/NS
dnstwist --fuzzers homoglyph,bitsquatting example.com    # class-scoped generation
urlcrazy example.com                                     # typo/variation set + popularity hints
# Flag mixed-script labels; an IDN renders on the wire as xn--... (punycode).
# An aged/expired domain with a CLEAN web-filter category delivers better -> reputation check only.
```

---

## Extended arsenal — deliverability & mail-auth alignment (SPF / DKIM / DMARC / TLS)

Deliverability testing measures whether the mail gateway + filters are a working control. Publish records on
the AUTHORIZED sender domain only; the aim is a measured delivery rate, never defeating a third party's filter.

```
# DNS on the authorized sender domain
example.com.                 TXT  "v=spf1 ip4:<sender-ip> ~all"
_dmarc.example.com.          TXT  "v=DMARC1; p=none; rua=mailto:soc@example.com"   # p=none for the test window
sel._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=<pubkey>"                     # sign with the matching selector
# PTR / rDNS of the sender IP should resolve back to the HELO name.
```
Alignment = From: domain == DKIM `d=` == SPF MAIL-FROM → DMARC "aligned" → inbox, not spam/reject.
```
# Confirm what the receiver saw (Gmail "Show original" / raw headers):
#   Authentication-Results: spf=pass dkim=pass dmarc=pass
# Warm the domain (low -> high send volume) before the window; check reputation + blocklists
#   (mail-scoring services, Spamhaus / Microsoft delisting if flagged).
# Valid TLS on the landing listener lifts click-through and avoids browser warnings:
certbot certonly --standalone -d phish.example.com       # bind the issued cert to the gophish listener
```

---

## Extended arsenal — credential-harvest page cloning (benign test-credential capture)

Clone the lure page to measure submit-rate, then make real-password capture IMPOSSIBLE by construction.

```
# Static clone, served read-only:
wget --mirror --page-requisites --convert-links --adjust-extension https://portal.example.com
goclone https://portal.example.com                       # downloads keeping relative structure
python3 -m http.server 8000                              # or import the clone as a gophish Landing Page
# In gophish: enable "Capture Submitted Data" but DISABLE "Capture Passwords".
```
BENIGN-capture contract (enforce ALL):
- Record the EVENT only: `{recipient-token, timestamp, "submitted"}` — never the password field value.
- If a value must transit, hash+discard server-side (keep a non-reversible marker), or accept-and-redirect to
  the awareness/training page without persisting the body.
- Seed with BENIGN TEST-credential markers (e.g. `test-user / TESTVALUE-<token>`); any real secret that slips
  in is sensitive → redact + purge immediately.
- Teardown: take the page offline + wipe captured rows once metrics are tallied (keep aggregate counts only).

---

## Extended arsenal — delivery-vector catalogue (CATALOGUED, not fired)

Inventory of vectors a real adversary uses, kept as a CONTROL CHECKLIST. In an authorized simulation these are
described + counted, NOT built, armed, or sent — no working malware, no live payload, no working exploit.

| Vector | Mechanism (one line) | Control it probes |
|---|---|---|
| Office macro (VBA) | AutoOpen / Document_Open fires on enable-content | macro policy / block-macros-from-internet |
| Remote template inject | DOCX pulls a remote `.dotm` | outbound-from-Office egress filtering |
| DDE / field codes | field/formula triggers execution | legacy-feature hardening |
| LNK loader | shortcut runs a staged command | attachment-type filtering |
| HTML smuggling | JS Blob reassembles a file client-side | gateway can't scan the blob → endpoint check |
| ISO / IMG / container | mounts, hides payload, strips Mark-of-the-Web | MOTW propagation / mount policy |
| CHM / OneNote / HTA / MSC | legacy execution containers | application allow-listing |
| QR / PDF redirector | image/doc defers the URL past the scanner | link-rewrite + QR-in-email awareness |
| Device-code / OAuth consent | victim authorizes an app — no password sent | conditional access + app-consent policy |

For any vector "delivered" in a simulation, measure ONLY the benign signal (open / click / enable-event) via
tracking; the payload body stays inert. Mark every row **"catalogued, not fired"** in the report.

---

## Extended arsenal — MFA-fatigue & real-time AiTM / consent-phishing (concepts)

Tests whether MFA + consent controls resist modern bypasses. High-impact → approval-gated; when exercised,
only against a CONSENTING test identity, no real session retained, torn down after.

| Concept | What it probes | Benign test shape |
|---|---|---|
| MFA fatigue / push bombing | approve-from-habit on repeated prompts | count prompts → approvals on a consented TEST account |
| Forced re-enrollment | self-service MFA reset abuse | can a reset be driven without strong proof |
| AiTM reverse-proxy relay | proxy relays creds + session cookie live (evilginx-class) | CATALOGUED; if run → TEST identity only, cookie not kept |
| Remote-browser / VNC lure | victim drives a real session in attacker view (EvilnoVNC-class) | CATALOGUED; TEST identity only |
| OAuth illicit consent | app-consent yields a token without a password | in-scope benign app, minimal scopes, revoke after |
| Device-code flow | victim enters a code that authorizes attacker device | measure grant on a TEST tenant/identity |

Measure the CONTROL outcome (did number-matching / consent-policy / conditional-access stop it?) as an
aggregate gap — never a named person. Revoke every token + app and clear any test session on teardown.

---

## Extended arsenal — vishing / smishing / help-desk pretext catalogue (authorized, benign)

Voice / SMS / live-chat channels against the authorized, consented population ONLY; honor telecom + SMS law
and the window. The script measures whether a scoped benign action occurs — no real secret is ever collected.

| Channel | Pretext family | Measured (benign) action |
|---|---|---|
| Vishing | IT / service-desk callback, benefits / HR | caller elicits a visit to the awareness page |
| Vishing | MFA reset / "read me your code" | whether help-desk resets without strong ID proof (test account) |
| Smishing | delivery / package, bank alert, doc-share | tracked-link click from a consented number |
| Live-chat / IM | internal-tool support, chat "device-link" QR | whether a device-link / QR is approved (test identity) |

Rules: authorized numbers / identities only; benign script; stop on distress; log every contact; outcomes are
aggregate (`contacted → engaged → action → reported`), never an individual named.

---

## Extended arsenal — MITRE ATT&CK mapping & derived control signals

| ATT&CK | Technique | Simulation counterpart |
|---|---|---|
| T1566.001 | Spearphishing Attachment | benign-attachment open rate |
| T1566.002 | Spearphishing Link | click + submit rate |
| T1566.003 | Spearphishing via Service | IM / consent-channel engagement |
| T1598 | Phishing for Information | vishing / smishing elicitation |
| T1621 | MFA Request Generation | push-bombing approve rate (test account) |
| T1656 | Impersonation | pretext plausibility vs report rate |

Derived signals to report (aggregate ONLY; the base funnel lives in **Metrics** above — this is the
measurement layer, not a second funnel):
- time-to-first-report + % who used the reporting path → detection/response health
- submit-rate & consent-grant rate → credential / consent hygiene
- delivered-rate → mail-filter efficacy ; approve-rate on MFA prompts → MFA resilience
- NO per-person leaderboard; every signal rolls up to a control, not a named human.
