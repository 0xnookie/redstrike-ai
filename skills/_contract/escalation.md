# escalation — before you call a high-prior surface clean, exhaust the ladder

Inherited by every **executor** (consult before marking a surface tested-and-clear with 0 findings)
and by `verify-base.md` (coverage audit, base check #5). This is the operational companion to
[`counterevidence.md`](counterevidence.md): that file says *"missing information is not proof of
safety"*; this one makes it a concrete, deterministic step so **"empty" cannot masquerade as
"clear"** — the quiet recall killer.

## The rule
A result of **0 findings** is only an acceptable clear when ONE of these holds:
1. the surface was **low-prior** — recon surfaced no signal that this class applies here; or
2. the surface was high-prior (or prior unknown) **and the class's escalation ladder was exhausted**
   (each step tried, or a step recorded as an **open-proof-gap** blocker — WAF / creds / env / no OOB).

A high-prior empty with ladder steps left is a **shallow clear** — NOT trustworthy. Escalate first.
"Unknown" prior is treated conservatively like high (recall-safe default, matching the coverage
"attempt all with no signals" policy).

## Deterministic helper
[`../../scripts/escalation.py`](../../scripts/escalation.py) encodes the ladders and the decision:
```python
import sys; sys.path.insert(0, "scripts"); import escalation
escalation.assess(class_id, findings_count, prior="high", escalations_done=[...], blockers=[...])
#   -> {"verdict": "found" | "clear-ok" | "clear-after-escalation" | "escalate", "remaining": [...]}
```
`verdict == "escalate"` ⇒ try `remaining` (ordered; a step matching an observed blocker is promoted
first) and record each attempt in `escalations_done` before re-assessing. Only `clear-ok` or
`clear-after-escalation` may close a surface with 0 findings.

## The ladders (grounded in the juice-shop recall run)
- **injection family** (sqli/nosql/ldap/ssti/cmd/deser/xxe/proto): `derive-not-assume` (UNION column
  count via [`sqli_union.py`](../../scripts/sqli_union.py) — the 10-vs-9 column lesson) → encoding
  ladder → waf-bypass → alt content-type → header injection → second-order → OOB.
- **xss family**: `browser-render` (client-side execution detection — DOM/Reflected only trip in a REAL
  browser) → API-inject bypassing the client sanitizer → context variants → header-XSS → stored
  cross-user → CSP-aware payload.
- **authz family** (idor/privesc/api/bola/graphql): second identity → sibling ids → verb swap →
  mass-assignment → nested/aliased refs.
- **auth family** (auth/jwt/oauth/crypto): `token-cookie-and-header` (forged token in BOTH the cookie
  AND the Authorization header — the JWT lesson) → alg-confusion → reset/recovery flaws →
  policy-safe spray → tamper+replay.
- **exposure family** (exposed-surface/secrets/file/lfi/upload): custom wordlist → filter bypass
  (null-byte/double-encode) → backup/VCS/temp extensions → auth-vs-unauth diff.
- **generic fallback**: re-trigger via a different path → escalate to the technique matching the
  observed blocker → widen the input space once.

## Above the floor — hypothesis-driven depth
The ladder above is the **FLOOR**: deterministic, class-generic, and unconditional on a high-prior
surface. It is NOT the ceiling. Once the ladder is exhausted on a high-value surface, the executor adds
a **target-specific** layer the generic ladder cannot encode: it forms **hypotheses** from the behaviour
it actually observed (a timing wobble, an error fragment, a response differential, a stack/header quirk)
and logs each as a structured record in `hypotheses.jsonl` — **hypothesis → test → outcome** (shape +
rules in [`hunter-base.md`](hunter-base.md) → "Hypothesis-driven depth"). This is purely the STRUCTURE
and LOGGING of reasoning — it introduces no new payloads; the probes stay within the class's existing
benign repertoire.

The decisive rule for recall: an **unresolved** hypothesis (one the executor formed but could not
confirm or refute — blocked, untested, out of budget) is an **open-proof-gap**, exactly like an
un-exhausted ladder step. A surface that still carries an unresolved hypothesis is a **shallow clear**,
not a clean one, and must not close clean. `verify-base.md` check #5 treats it as a coverage gap.

## Closure
Record the outcome so a clear carries its effort: either a finding, or `clear-after-escalation` with
the ladder steps tried, or a `blocked` / open-proof-gap naming the specific blocker. A bare
"attempted, nothing found" on a high-prior surface with no escalation recorded is a coverage gap,
not a clean result. **An unresolved `hypotheses.jsonl` record is likewise an open-proof-gap** — a
surface cannot be closed clean while one is outstanding, any more than it can with a ladder step left.
