# CRLF Injection (HTTP response splitting / header injection) — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the CRLF gauntlet. Confirmed = a user-controlled value broke into the HTTP RESPONSE
HEADER block so an attacker-chosen header ACTUALLY TOOK EFFECT in the response — the injected header/marker
is present in the RESPONSE HEADER block (captured raw headers), OR a genuine response-split start-line (a
second `HTTP/1.x NNN` status line) is parsed from the raw response — AND removing the CR/LF restores the
normal response (causal differential). Re-run the benign took-effect + causality proof.

## CRLF false-positive gauntlet (base check #3)
- [ ] **The injected header/marker is in the RESPONSE HEADER block (or a real split started) — not a body
      reflection, not a 200/302.** Evidence shows the attacker header actually landed in the response-header
      set (the raw `curl -sD-` / interceptor header block contains the injected `X-`/`Set-Cookie` marker),
      OR the raw response contains a second `HTTP/1.x NNN` start-line (a genuine response split). A payload
      that is only **reflected in the response BODY** is NOT this class (→ `xss-*`), and a request that
      merely returned `200`/`302` without a validation error is NOT proof — reject a body-only or
      acceptance-only finding here.
- [ ] **CR/LF into the HTTP header block was the break, causally.** The attacker value introduced a new/
      overridden response header (or split the block) because CR/LF (or `\n` alone, encoded `%0d%0a`,
      double-encoded `%250d%250a`, or a null-byte-prefixed sequence) was not stripped before the value
      reached the response-header layer. The causal differential is decisive: **re-sending WITHOUT the
      CR/LF makes the injected header / second response disappear**. If removing the CR/LF leaves the same
      output, it is not a CRLF break — reject.
- [ ] **Driven by attacker-controlled input, reproducibly.** The payload was attacker-authored and the
      took-effect result reproduces (≥2 sends).
- [ ] **De-dup / correct ownership (defer, don't claim).** This finding is the HTTP response-HEADER
      manipulation / response split, NOT: a payload that lands/executes in the response **BODY**
      (reflected/stored HTML/JS — a **different class**, → `xss-*`); an attacker controlling the redirect
      **destination/host** in the `Location` value rather than splitting the header block (→ `open-redirect`
      / `host-header`); a poisoned response a shared cache serves **cross-user** (→ `cache-poisoning` — that
      leg is confirmed there); CR/LF into a generated **email** header block (→ `email-injection`). The
      downstream impact of a split (XSS / cache poisoning) is confirmed by the owning class — don't claim it
      without that evidence.
- [ ] **Benign + approved + scope.** Self-scoped with a unique cache-buster so only the tester's own request
      was affected; a benign marker header only; no full malicious second response served to real users; no
      shared-cache poisoning performed here; any secret a captured header carries redacted to a fingerprint;
      approved; in scope.

## CVSS integrity
A response split that enables cross-user XSS or cache poisoning → High (coordinate the downstream leg with
`xss-*` / `cache-poisoning`); a response-header injection with demonstrated impact (session fixation via an
injected `Set-Cookie`, a security-relevant header override) → Medium; a header add with no demonstrated
impact → Low. Note the **declining prevalence** (modern servers/frameworks strip raw header CR/LF) — justify
from the header that TOOK EFFECT in the response and its demonstrated impact, not from a body reflection or
the mere acceptance of a payload.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "crlf-injection-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["injected %0d%0aX-CRLF-Test:rs-crlf-9k into the 'redirect' param -> raw response-header block contains 'X-CRLF-Test: rs-crlf-9k' (Location sink); removing the CR/LF drops the header (causal, 2/2); self-scoped cache-buster; not a body reflection (not xss), not a redirect-host change (not open-redirect/host-header), no shared-cache poisoning (cache-poisoning deferred)"],
  "scope_ok": true, "notes": "benign marker header; self-scoped cache-buster; approved; body-landing / redirect-host / cache / email variants deferred" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
