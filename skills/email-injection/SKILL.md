# Email Injection Agent  (SMTP / email header injection — CWE-93)

> ATOMIC single agent (feeder: `flow-context`) — CR/LF into a user value that reaches a generated email, so an
> attacker adds/overrides an email header (`Bcc`/`Cc`/`Reply-To`/`Subject`/`Content-Type`/MIME) or breaks into
> the body. The email-header variant of CRLF injection; distinct from the HTTP-response CRLF surface.
> ACTIVE (sends a real outbound email), findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## De-dup boundary (what this skill OWNS vs hands off)
- **OWNS — email/SMTP header injection:** a user-controlled value reaching a generated email WITHOUT CR/LF
  stripping, letting the attacker add or override an EMAIL header (`Bcc`/`Cc` exfil, `Reply-To` redirect,
  `Subject`/arbitrary override, `Content-Type`/MIME body & structure break), PROVEN by the injected header
  actually taking effect — a benign copy reaching a tester-owned mailbox, a reply redirected, or the injected
  header observably present in the delivered message.
- **HANDS OFF:** a CR/LF that splits the **HTTP response** (response splitting / HTTP header injection /
  set-cookie smuggle) is a **different class** — not this skill; an attacker controlling the reset-link
  **host/domain** via the `Host`/forwarding header → `host-header`; duplicated/polluted request parameters →
  `parameter-pollution`; injected HTML/JS that executes in a webmail/app **HTTP response** → `xss-*`; the
  validity/impact of an exfiltrated secret → `secrets` / the owning auth class.
- A form that merely **returns 200/accepts** a CRLF-ish payload (no validation error) is NOT a finding — this
  skill must show the injected header TOOK EFFECT (copy received / reply redirected / header present in the mail).

## Interview
- **STEPS:** ingest the email-sending flows from `flow-context` → identify which user field lands in the mail header block (signup, password-reset, contact, invite, invoice, share, notifications) → inject header-breaking sequences (CR/LF + `Bcc`/`Cc`/`Reply-To`/`Subject`/MIME) benignly against a TESTER-OWNED recipient → confirm the injected header ACTUALLY took effect (copy to tester mailbox / reply redirected / header present in the delivered message) → rate → emit → review → verify.
- **TOOLS:** interceptor, `curl`/`jq`, a tester-owned mailbox + OOB (SMTP+HTTP) collector (`interactsh`), `refs/email_injection.md`; hand HTTP-response CRLF to the HTTP-header-split surface, reset-link host control to `host-header`, dup-param precedence to `parameter-pollution`, in-page script execution to `xss-*`.
- **GOAL:** Confirm email header injection — a user-controlled value breaks into the email header block so an attacker-chosen header (`Bcc`/`Cc`/`Reply-To`/`Subject`/`Content-Type`) takes effect — proven benignly against a tester-owned recipient. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `email_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `flow-context/flow_context.json` (the actions that send a user-input-bearing email) + `js-analysis/out/<site>/findings/{endpoints,params,apis}.jsonl` + `content-discovery/` (the concrete forms/fields) + `scope.yaml` (`oob.collaborator` + a tester-owned recipient). `refs/` = `email_injection.md`. Chains FROM `flow-context` / recon; chains TO `reporting` (+ `secrets` / the auth class for an exfiltrated reset token's downstream impact).
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove email/SMTP header injection, benignly: an attacker-controlled header took effect in a generated email
(copy to a tester mailbox / reply redirected / header present in the delivered message). Emit `findings.json`
(`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The email-sending flows and which user-controlled field lands in the mail header block (signup/verification,
  password-reset, contact/feedback, invite, invoice/order, share/notify, newsletter)
- A header break that TOOK EFFECT: an injected `Bcc`/`Cc` delivered a copy to a tester mailbox, an injected
  `Reply-To` redirected replies, or an injected `Subject`/`Content-Type`/MIME header is present in the mail
- Benign proof — the tester-mailbox copy / redirected reply / captured delivered header — NOT a bare 200/accepted,
  NOT a reflected payload; any carried secret (reset link/token, invoice) redacted to a fingerprint

## Steps  (action · tool · output)
1. Ingest email-sending flows + the user fields that reach each mail · `jq flow_context.json` + recon · (into tests)
2. Map carrier per flow (HTML form / JSON / query) + the high-value payload the mail carries (reset link/token, invite, invoice) · interceptor · `email_tests.jsonl`
3. Bcc/Cc exfil: inject `%0aBcc:tester@OOB` into a user field (LF-only → CRLF → raw `\r\n`) · `curl`/interceptor · `email_tests.jsonl`
4. Reply-To redirect: inject `%0aReply-To:tester@OOB` · `curl`/interceptor · `email_tests.jsonl`
5. Subject / arbitrary header override + Content-Type/MIME body-and-structure break · `curl`/interceptor · `email_tests.jsonl`
6. Confirm the header TOOK EFFECT: copy at tester mailbox / redirected reply / header present in the delivered message (attributable OOB SMTP+HTTP) · mailbox + OOB · `callbacks.jsonl`
7. Confirm benignly (single send, tester recipient), redact any carried secret to a fingerprint · synth · `poc/<id>/`
8. Rate (CVSS) + write finding · synth · `findings.json`
9. Emit report · synth · `report.md`
10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- interceptor, `curl`/`jq`, a tester-owned mailbox + OOB (SMTP+HTTP) collector (`interactsh-client`), `refs/email_injection.md`
- hand off: HTTP-response CRLF → the HTTP-header-split surface (different class); reset-link host control → `host-header`; dup-param precedence → `parameter-pollution`; in-page script execution → `xss-*`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `flow-context/flow_context.json` (the actions that send a user-input-bearing email + the field that lands in the mail)
- `js-analysis/out/<site>/findings/{endpoints,params,apis}.jsonl` + `content-discovery/` (concrete forms/fields)
- `scope.yaml` (`oob.collaborator` + a tester-owned recipient mailbox), `refs/email_injection.md`

## Outputs
`email_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** email-sending-flow ingest + field/carrier mapping + the LF-only/CRLF probe set.
- **Phase 2 (target-specific):** Bcc/Cc exfil + Reply-To redirect + Subject/Content-Type/MIME break + benign took-effect confirmation + rating (approval-gated).

## Safety
Sending a probe **generates a real outbound email** — **approval-gated**; confirm with BENIGN effects only (a
single confirming send to a **tester-owned** recipient, the injected `Bcc`/`Reply-To` pointing only at a
tester mailbox / OOB collector). **Never** spoof or send mail to uninvolved third parties, **never** mass-mail
(one confirming send per technique, not a burst). Redact any secret the captured mail carries (reset link/
token, invoice, magic-link) to a fingerprint, and delete the captured copies that hold a real secret after
confirming. If a payload was STORED (e.g. a persisted profile display-name with an injected `Bcc`) that would
re-send on a later legitimate trigger, remove it and record the removal (`cleanup.md`). HTTP-response CRLF /
reset-link host control / dup-param precedence / in-page script execution are handed off (de-dupe). Kill
switch; scope to authorized endpoints; rate-limit; audit-log.
