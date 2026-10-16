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
