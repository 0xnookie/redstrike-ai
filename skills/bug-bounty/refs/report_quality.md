# Bug-bounty submission quality
# What turns an accepted finding into a submission a triager can reproduce, rate, and pay fast.
# ONE finding = ONE submission (triager-facing). The multi-finding CLIENT report lives in
# `reporting/refs/report_template.md`; this is the per-submission bar for `submissions/`.

## The bar (self-check before a draft leaves `submissions/`)
A reviewer who has never seen the target must reproduce the bug from the text alone, agree on its
impact, and find nothing missing or extraneous. Each box is checkable against the draft:

- [ ] **Title** names class + exact location + effect — specific, not a bare category.
- [ ] **Reproduction** is numbered and complete: URL(s), method, parameter(s), account/role, preconditions.
- [ ] **Expected vs. actual** behavior is stated explicitly.
- [ ] **Impact** gives the attacker scenario + concrete loss, and matches the claimed severity.
- [ ] **Proof** is attached where it carries the claim (request/response, screenshot, short video, payload).
- [ ] **Formatting**: every log/request/response/code sample is in a fenced block; prose uses headings + bullets.
- [ ] **Signal only** — no filler, no unrelated recon dump, no speculation stated as fact.
- [ ] **Scope + dedup**: asset is in program scope; not a known issue / internal duplicate.
- [ ] **Secrets redacted** to fingerprints; evidence referenced from the vault, never pasted raw.

## Title — specific and scannable
The title is read first and sorts the queue. Name three things: **class · location · effect.**
| Weak | Strong |
|---|---|
| `XSS in web app` | `Stored XSS in displayName (POST /api/profile) executes in the admin user-list view` |
| `IDOR` | `IDOR in GET /api/v2/invoices/{id} — any user reads another tenant's invoice` |
| `SSRF` | `Blind SSRF via webhook_url (POST /integrations) reaches the cloud metadata endpoint` |

## Reproduction — a stranger can follow it
Numbered, deterministic, minimal — one path to repro, not three. Include:
- the exact **endpoint + HTTP method**;
- the **parameter(s)** carrying the input, and the **payload** itself (in a code block);
- the **account / role / tenant** used (and a *second* identity for authz bugs — the whole point is A reaching B);
- any **precondition or state** (logged in as X, a record must exist, a feature flag);
- the **observable confirmation** (rendered marker, response differential, attributable OOB callback id).
Prefer a raw HTTP request/response pair over prose describing it.

## Expected vs. actual
Two lines that frame the bug for someone who doesn't know the app's intent:
- **Expected:** the server rejects / scopes to the owner / encodes the value …
- **Actual:** it accepts / crosses the tenant boundary / executes the value …

## Impact — earn the severity
State the **attacker's path** and the **concrete loss**, then tie it to the claimed rating
(CVSS vector / program bucket). Answer: *who* is the attacker (unauthenticated? any registered user?
a neighbouring tenant?), *what* they do, *what* they gain, and at *what scale*. The demonstrated impact
and the severity must agree — don't assert RCE from a reflected value, and don't undersell a cross-tenant
read as "just an info leak". Severity the evidence doesn't support is the fastest route to a downgrade.

## Proof — evidence, not decoration
Attach what lets a triager believe the claim without re-deriving it:
- **HTTP request/response** — the primary proof for web bugs; in code blocks, headers trimmed to what matters.
- **Screenshot** of the triggered/rendered state, with the relevant region annotated.
- **Short video** for multi-step, timing/race, or UI-redress bugs a still can't capture.
- **Payload / PoC** — the *minimal benign* proof (marker / canary / OOB id), never a weaponized or
  destructive variant.
Reference each artifact from the engagement evidence vault; secrets appear only as redacted fingerprints.

## Formatting — reduce the reader's work
- Fence every log, request, response, and code sample (```); never drop multi-line logs into prose.
- Headings + bullets; one idea per line.
- Complete but concise — cut anything unrelated to the security team's decision. A triager skimming dozens
  of reports rewards signal density.
- Markdown that actually renders — verify tables, links, and code fences in the program's report form.

## What sinks a submission
- Vague or partial reproduction — the single most common "needs more info" / reject cause.
- A payload with no "so what" — no impact narrative.
- Severity inflation the evidence can't back.
- Wall-of-text, unformatted logs, or an irrelevant recon dump.
- An out-of-scope asset, or a duplicate of a known/already-reported issue (check *before* drafting).

## Submission skeleton (one finding)
```
Title: <class> in <location> — <effect>

## Summary
<1–2 sentences: what the bug is and why it matters.>

## Steps to reproduce
1. <as account/role …>
2. <request to endpoint, parameter = payload>
3. <observe: the confirming signal>

## Expected vs. actual
- Expected: <…>
- Actual:   <…>

## Impact
<attacker + concrete loss + scale>  →  severity <CVSS vector / bucket>

## Proof
<request/response block; screenshot/video ref; payload = benign marker>

## Remediation (optional)
<specific, testable fix>
```

## Pre-send gate (human)
Submitting is outward-facing: the agent produces the draft in `submissions/`; a human sends it.
Before sending, re-read once *as the triager* — reproduce from the steps alone, confirm scope +
non-duplicate, confirm severity matches the proof, confirm no raw secrets. Only `accepted`, in-scope,
non-duplicate findings ever become submissions.
