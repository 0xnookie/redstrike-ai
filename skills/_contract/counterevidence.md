# counterevidence — argue the opposing case BEFORE you file (and before you call a surface clean)

Inherited by every **executor** (consult before emitting a finding, and before marking a surface
tested-and-clear) and by `verify-base.md` (base check #3 false-positive gauntlet + #5 coverage audit).
It is the inverse of a per-skill gauntlet: that one stops false **positives**; this also stops false
**negatives** — dismissing a real candidate for an invalid reason. "Missing information is not proof of safety."

## Before you emit a finding
1. Switch to skeptic and try to DISPROVE your own claim. Falsification is worth as much as confirmation.
2. Re-trigger through a **different** path / an independent command — not by restating the original
   output. One observation is a hypothesis; a second, mechanistically-different one is evidence.
3. State your **assumptions** and the real **constraints** you hit (auth, WAF, env, timing).
4. Set confidence honestly: a static / inference-only trace is at best medium until dynamically shown.

## Not proof of a vulnerability (do NOT mark these "confirmed")
- a version / CVE match — reachability is still unproven (that is `tentative` / `cve-intelligence`, not a hit).
- "looks injectable" / reflected metacharacters — reflection, or a 500, is not execution.
- circular evidence — the "proof" just restates the claim in other words.
- querying a CVE database / diffing patch versions as a substitute for actually triggering it.
- a scanner line with no corroborating request/response you can reproduce.

## Does NOT rule a candidate out (invalid reasons to call it clean)
- "a library/helper handles it" — without checking THAT call in ITS context.
- a control on a **different** route / caller / job than the one in question.
- a control that runs **too late** (after the fetch / redirect / write already happened).
- fail-open inside a `try/except` or error path.
- a **safe sibling** call site — it says nothing about the others; each instance is its own candidate.
- "internal-only" / "needs auth" — lowers severity or confidence, it does not unmake the finding.
- "couldn't build the PoC / missing creds / blocked by WAF" — that is an OPEN PROOF-GAP, not safety.

## Negative control (corroboration)
A payload that SHOULD work if the bug were real is rejected, while a benign variant of the same request
succeeds → the difference is attributable to the bug, not to noise.

## Three closure states for every candidate
- **confirmed** — demonstrated per the skill's `verify.md`.
- **ruled out** — disproven WITH evidence (a negative control, or a verified in-path control). "I didn't
  see it" is not ruling out.
- **open proof-gap** — real-looking but undemonstrable here (env / creds / WAF). Carry it as a caveat
  (finding `status: blocked`, or a `needs-evidence` note) — never silently drop it.
