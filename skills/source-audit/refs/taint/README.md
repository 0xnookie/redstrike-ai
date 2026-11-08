# Taint rule packs — source→sink reachability (D1)

These are **semgrep `mode: taint`** rulesets. Unlike the flat dangerous-sink grep in
`../source_audit.md` (which flags a sink wherever it appears), a taint rule only fires when
attacker **input (source)** provably **reaches a dangerous sink** **without passing a sanitizer**.
That turns "this sink exists" into "this sink is *reachable*" — the difference between a regex
scanner and a reachability-aware feeder.

A taint match is still a **CANDIDATE**, never a finding. source-audit stays a feeder: the routed
executor PROVES it against the running target. Taint raises *lead quality*, not autonomy.

## Files
| File | Languages | Routes covered |
|------|-----------|----------------|
| `php.yaml` | php | command-injection · path-traversal-lfi · sqli-inband · deserialization · xss-reflected · ssrf-inband |
| `python.yaml` | python | command-injection · deserialization · ssti · sqli-inband · path-traversal-lfi · ssrf-inband |
| `javascript.yaml` | javascript, typescript (server-side) | command-injection · sqli-inband · path-traversal-lfi · ssrf-inband · xss-reflected |
| `java.yaml` | java | command-injection · deserialization · sqli-inband · path-traversal-lfi · ssrf-inband |

Client-side DOM source→sink XSS stays with `js-analysis` / `xss-dom`. Go/Ruby/Rust/C taint packs
are a follow-up — those languages still get the flat grep pass from `source_audit.md`.

## Rule contract
Every rule carries `metadata.route` ∈ the `candidates[].route` enum in
`_contract/source_context.schema.json`, so a match maps straight to the executor that confirms it.
`metadata.category` + `metadata.cwe` + `metadata.confidence` ride along. Each rule declares:
`pattern-sources` (attacker input) · `pattern-sinks` (dangerous call) · `pattern-sanitizers`
(functions that neutralise the flow).

## Run
```bash
semgrep --config skills/source-audit/refs/taint/ --json -o logs/semgrep-taint.json <src>
```
Then, per `candidates[]` entry, set `taint`:
```json
"taint": { "reachable": true, "engine": "semgrep-taint",
           "rule_id": "php-taint-command-injection",
           "source": "$_GET", "sink": "system" }
```
Mapping taint → `confidence`:
- taint **reachable** (unsanitized source→sink)  → `confidence: high`
- sink found by grep but **no** taint flow         → `confidence: low` (present-but-unproven; keep as a lead, say so)
- taint flow but a **sanitizer** broke it (`sanitized: true`) → drop, or keep as `low` with a note

## Validate / extend
```bash
semgrep --validate --config skills/source-audit/refs/taint/        # syntax + metadata
```
Adding a language: new `<lang>.yaml`, one rule per route, `metadata.route` from the enum, and a
tiny vulnerable+sanitized sample proving the sink fires and the sanitizer suppresses before you
trust it. A sanitizer false-negative (sink fires through a real sanitizer) is a rule bug — fix the
`pattern-sanitizers`, don't ship noise.
