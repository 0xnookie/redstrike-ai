# Email Injection (SMTP / email header injection) — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the email-injection gauntlet. Confirmed = a user-controlled value broke into the email
header block so an attacker-chosen header ACTUALLY TOOK EFFECT in a generated email — a benign copy reached a
tester-owned mailbox (injected `Bcc`/`Cc`), a reply was redirected to a tester mailbox (injected `Reply-To`),
or the injected header is observably present in the delivered message (captured raw headers / rendered HTML
from an injected `Content-Type`) — proven benignly. Re-run the benign took-effect proof.

## Email-injection false-positive gauntlet (base check #3)
- [ ] **The injected header TOOK EFFECT — not a mere 200/accepted.** Evidence shows the attacker-controlled
      header actually landed in a generated email: a benign COPY of the outbound mail reached a tester-owned
      mailbox (injected `Bcc`/`Cc`), a reply was REDIRECTED to a tester mailbox (injected `Reply-To`), or the
      injected header is OBSERVABLY PRESENT in the delivered message (raw headers, or attacker HTML rendered
      from an injected `Content-Type`). A form that returned `200`/`302` and simply did not show a validation
      error after a CRLF-ish payload is NOT proof — the app may strip CR/LF downstream, the mailer may reject
      the header, or no mail may be sent. Reject an acceptance-only or reflection-only finding here.
- [ ] **CR/LF into the EMAIL header block was the break.** The attacker value introduced a new/overridden
      header because CR/LF (or `\n` alone, or a null-byte-prefixed sequence) was not stripped before the value
      reached the email header set — attacker-controlled header content was treated as a legitimate header.
- [ ] **Driven by attacker-controlled input, reproducibly.** The payload was attacker-authored and the
      took-effect result reproduces (≥2 benign sends).
- [ ] **De-dup / correct ownership (defer, don't claim).** This finding is the EMAIL header manipulation + its
      mail-layer impact, NOT: a CR/LF that splits the **HTTP response** (response splitting / HTTP header
      injection / set-cookie — a **different class**, reject/route it, do not claim it here); an attacker
      controlling the reset-link **host/domain** via the `Host`/forwarding header (→ `host-header`);
      duplicated/polluted request parameters (→ `parameter-pollution`); injected HTML/JS that executes in a
      webmail/app **HTTP response** rather than the mail (→ `xss-*`). The exfiltrated secret's downstream
      validity/impact is confirmed by `secrets` / the owning auth class — don't claim that impact without it.
- [ ] **Benign + approved + scope.** A single confirming send per technique to a TESTER-OWNED recipient only;
      no mail to uninvolved third parties; no mass mail; any secret the captured mail carries (reset link/token,
      magic-link, invoice) redacted to a fingerprint and the real copy deleted; approved; any STORED payload
      that would re-send on a later legitimate trigger removed (cleanup.md).

## CVSS integrity
`Bcc`/`Cc` exfil of a secret-bearing mail (password-reset link/token, magic-link, invoice, invite) → High (an
account-takeover / sensitive-data-exfil primitive — coordinate the token's downstream leg with `secrets` / the
auth class); `Reply-To` redirect or forced-HTML in-mail phishing → Medium (social-engineering primitive, no
secret directly exfiltrated); a header override with no demonstrated impact → Low. Justify from the header that
TOOK EFFECT and its demonstrated impact, not from the mere acceptance of a payload.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "email-injection-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["injected %0aBcc:tester@<oob> into the password-reset 'email' field -> a copy of the reset mail (reset link redacted to a fingerprint) was delivered to the tester mailbox; reproduced 2/2; single benign send; not an HTTP-response CRLF, not host-header"],
  "scope_ok": true, "notes": "benign single send to tester recipient; captured secret redacted + deleted; approved; HTTP-response CRLF / host control deferred" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
