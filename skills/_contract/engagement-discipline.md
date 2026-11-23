# Engagement discipline — always-on anti-pattern reminders

A short cross-cutting reminder carried into every autonomous leg (launcher-injected into the appended
system prompt). It does not replace any skill's `verify.md` — it front-loads the recurring mistakes so
they are avoided *before* the reviewer, not only caught at verify time. Methodology, not a checklist to
emit; the per-class gauntlet + `counterevidence.md` still apply.

- **Reflection is not execution.** A payload echoed in the response, a metacharacter surviving, or a 500
  is a candidate — not a finding. Prove the sink actually *ran* the input (rendered/evaluated/executed).
- **IDOR / BOLA need two distinct identities.** Reading your *own* object, or data your role may see, is
  not a cross-tenant bug. Demonstrate account A reaching account B's resource because the ownership check
  is missing — one identity proves nothing.
- **A WAF/403 on a path means the path EXISTS, not that it is vulnerable.** A block is a surface signal to
  pivot on, never a finding on its own, and never a target defense to burn turns bypassing.
- **Error-message / behaviour divergence is a SIGNAL, not a finding.** A timing delta, a different error,
  a status flip tells you *where to look next* — confirm the underlying bug before you file it.
- **Prove blind bugs with an attributable OOB callback or controlled timing — quantify, don't guess.** Tie
  the callback to *your* unique token (not a scanner/preview bot); for timing, show a reproducible,
  condition-controlled differential against a baseline. "It felt slow" is not proof.
- **Benign PoC only; defer destructive / exploit / RCE steps to the approval gate.** Demonstrate impact
  with the least-harmful proof. A step that is not pre-allowed DEFERS for operator approval — record it,
  skip it, continue; a deferral is the intended gate, never an error to route around.
- **A feeder-class finding is not a report until chained or ruled out.** An open redirect, a reflected
  parameter, a disclosed version, a secret — carry impact to a concrete outcome (chain it) or close it as
  ruled-out-with-evidence / open-proof-gap. Do not silently drop a real candidate; do not oversell a lead.
