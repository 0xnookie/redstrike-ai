# DOM XSS — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. Runs as a SUBAGENT with its own fresh context.
# Precondition: review.md (mechanical) already PASSED.
# Input: findings.json + poc/ + taint_flows.json. Output: each finding's review{} block
# (schema: _contract/finding.schema.json) + an overall verdict.

Run the 7 base checks (verify-base.md) on EVERY finding, plus the DOM-XSS gauntlet below.
DOM XSS is proven by a CLIENT-SIDE taint path that executes — not by a value appearing in the DOM.
Re-execute the crafted URL / postMessage in a headless browser and watch the sink fire.

## DOM-XSS false-positive gauntlet (base check #3)

For each finding you MUST rule out every item or it is NOT confirmed:

- [ ] **Real source→sink taint path.** `poc/<id>/` has a devtools trace (or breakpoint evidence)
      showing the controllable source reaching the sink — not a coincidental same-looking value.
      `taint_flows.json` references the path. No trace ⇒ `needs-evidence`.
- [ ] **Source is attacker-controllable.** hash / search / `window.name` / `document.referrer` /
      `document.URL`, or a `postMessage` whose handler **lacks/misvalidates `origin`** (an
      origin-checked handler is not cross-origin exploitable), or a storage value with a realistic
      set path. Otherwise reject.
- [ ] **Executes CLIENT-SIDE ONLY.** Reproduction is a crafted URL / `postMessage` with NO
      server-side state or reflection. If the sink value actually came from a server response, it
      is `xss-reflected`/`xss-stored` — reclassify, do not report as DOM. (Hash never reaches the
      server; confirm the payload isn't also server-reflected.)
- [ ] **Sink truly executes.** The sink runs code (e.g. `innerHTML` with `<img onerror>`/`<svg>`,
      `eval`, `location='javascript:'`) — not inert text (`<script>` via `innerHTML` does NOT run;
      a value merely written as text content is not XSS).
- [ ] **Trusted Types / CSP.** If TT or CSP enforces and blocks the sink, the evidence must show
      execution anyway; otherwise downgrade to info ("DOM flow present, non-executing under TT/CSP").
- [ ] **Delivery is realistic.** Hash/URL delivery = victim opens an attacker link (valid).
      `postMessage`/`window.name` = attacker page/iframe (note the delivery in the PoC). Not a
      flow only reachable via the tester's own devtools/console.
- [ ] **In scope.** `asset` ∈ `scope.yaml`.

## CVSS integrity (base check #4)
Typically `AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` (victim opens a crafted link), comparable to
reflected. Raise only with evidence — e.g. a prototype-pollution gadget chain reaching a
higher-impact sink, or `S:C` on a context jump. No interaction at all (auto-firing source) may
drop `UI:R` — justify from the trace.

## Verdict (write into each finding's review{} block)
```json
"review": {
  "verdict": "accepted | rejected | needs-evidence",
  "reviewer": "xss-dom-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["hash → location.hash → $().html sink traced; executes client-side; not server-reflected; no Trusted Types"],
  "scope_ok": true,
  "notes": "re-executed crafted URL headless; img onerror fired from location.hash sink"
}
```
- `accepted` → finding `status: verified`; flows to reporting.
- `rejected` / `needs-evidence` → bounce to executor; re-run the failed step; do NOT report.
