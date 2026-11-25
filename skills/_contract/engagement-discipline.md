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
- **No ad-hoc — every active probe runs INSIDE a skill.** Never break out of the framework to run a loose
  `curl`/`python`/`urllib` probe whose output lands only in the terminal. An active probe runs inside its
  executor skill, PERSISTS to that skill's `findings.json`, and is gated by its independent `*-verify`
  reviewer — a probe whose result was not persisted and reviewed **did not happen**: it is unreproducible,
  invisible to the ledgers, and can never become a finding. (One-off single `curl` to confirm a signature is
  the only exception, per `tooling.md`.) This is the orchestrator's no-ad-hoc invariant.
- **Don't get your egress BANNED — a WAF IP-reputation block burns the whole engagement, not one host.**
  Obvious attack-signature strings (`/etc/passwd`, `{{7*7}}`, `' OR '1'='1`) blasted broadly trip the WAF's
  IP-reputation ban, after which **every in-scope host returns the block page from your IP** — recon that was
  200 goes 403 estate-wide. Fingerprint the WAF FIRST (`wafw00f`), keep broad scans WAF-safe (detection-only,
  rate-capped, not raw signatures), and the moment a 403/429 shell appears across hosts that were just
  working, **HALT — do not keep probing a blocked egress** (field lesson: one careless signature flood flipped
  ~1200 recon-200 hosts to the gateway's 403 shell off a single egress). See `anti-automation-ladder.md` and
  `skills/waf-bypass/`.
- **A FORK/subagent executor cannot gate itself — hand findings back; the PARENT runs the reviewer + writes
  `report.md`.** An executor running inside a `fork`/`Agent` subagent can neither spawn its `<class>-verify`
  reviewer (no nested delegation) nor write `report.md` (harness-blocked). So it writes only its
  `findings.json` with the `review{}` block UNSET (never self-attest a verdict) and the orchestrator runs the
  independent reviewer + writes the report. A fork finding with no roster `*-verify` reviewer is an un-gated
  finding — the completion gate HARD-FAILS it before a report. See `verify-base.md` → "Independent review is
  mandatory" and the orchestrator §2b.
- **Stay inside the APPROVED benign-probe envelope — don't drift a marker into exploitation.** The probe you
  send must be the benign one the RoE approved, not an escalation of it: a stored-XSS validation marker is the
  approved NON-executing set (inert tags + raw metacharacters), NOT `<script>`/event-handler/`javascript:`
  payloads (those need a separate execution-proof approval on a non-public surface); an SSRF *feeder* probe
  confirms a fetch of an EXTERNAL benign OOB URL, NOT a hit on internal/metadata (`169.254.169.254`, loopback,
  RFC1918) — that is the approval-gated variant's job. Escalating a benign marker toward impact without the
  gate is the drift an external guardrail should never have to catch.
- **Session-liveness preflight before an authed hunt — an expired token fails OPAQUELY.** A test-account
  session (especially a ~1h JWT) can expire mid-engagement and then silently return `401`/`403`, wasting
  effort across leads that read as "clean/blocked". Before an authed executor spends a lead, cheaply check
  liveness — decode the JWT `exp` when the session token is a JWT (zero network), else one benign authed probe
  — and on expiry emit a clear **"session expired → re-capture needed"** block and refresh, rather than
  interpreting the Forbidden as a finding-free surface. See `browser-session.md` → "Deterministic session
  refresh".
