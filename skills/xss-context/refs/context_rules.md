# Reflection context classification + variant routing (steps 5, 9)

Classify by WHERE the marker landed in the response/DOM. The context decides which
payload family the variant agent will need (see `xss-reflected/refs/payloads_by_context.md`).

## Context → label (write into `reflection.contexts[]`)

| The marker landed... | label | breakout needed |
|---|---|---|
| in text between tags | `html_body` | introduce a tag |
| inside `attr="…MARKER…"` | `attr_quoted` | close quote + tag |
| inside `attr=…MARKER…` (no quotes) | `attr_unquoted` | space + event handler |
| inside `<script> var x='…MARKER…'` | `js_string` | close quote/`;` |
| inside `` `…MARKER…` `` | `js_template` | `${…}` |
| in `href`/`src`/`action` URL | `uri` | `javascript:` scheme |
| inside `<!-- MARKER -->` | `comment` | close comment |
| inside `<style>` | `style` | CSS/expression (rarely exec) |
| as raw code in a `<script>` block | `script_block` | direct expression |

Record `encoded: true` when the app HTML/JS/URL-encodes the breakout chars for that
context (the variant must then find a bypass, or the point is inert).

## Variant routing (write `variant_hint[]`)

- `reflects == true && persists == false && server-reflected` → **reflected**
- `persists == true` (marker resurfaces on another view) → **stored** (+ record `persist_surface`)
- `source == fragment`, or value flows to a sink client-side only (see `dom_flows.json`) → **dom**
- accepted but no visible reflection (async / server-processed / out-of-band) → **blind**

A single point may carry several hints (e.g. reflected **and** stored). List all; the
variant agents de-duplicate findings across each other during their `verify.md` pass.

## CSP interaction
Pair every routing with the CSP posture (`csp.json`). `blocks_inline`/`trusted_types`
downgrades inline-handler payloads — note `candidate_bypasses` (allowed JSONP/CDN
sources, missing `object-src`/`base-uri`) so the variant doesn't waste cycles on
payloads the policy will kill.

---

## Extended arsenal — reflection profiling (occurrence count + confidence)

Classification above labels *a* reflection; a thorough point is profiled, not sampled.

### Count every occurrence
One marker can come back N times in one response, each in a *different* context (e.g. once
in `html_body`, once inside `value="…"`, once in a `<script>` string). Classify EACH
occurrence separately, list every distinct label in `reflection.contexts[]`, and note the
count + positions in `evidence`. The **easiest-to-break** occurrence drives the variant —
don't stop at the first hit; a hard-encoded body reflection and a raw attribute reflection
of the same marker are one point with two very different odds.

### Per-char survival fingerprint (deepen the encoding canary)
Beyond the one-shot canary, send the breakout set one char at a time and record the survivor
set **per context** — the chars that matter: `<` `>` `"` `'` backtick `/` `=` `(` `)` `;` `{`
`}` and space. The variant then
synthesizes payloads ONLY from survivors — a payload that needs a stripped char is inert, so
skip it instead of burning WAF budget on it. This survivor map is the filter fingerprint the
`xss-reflected` / `waf-bypass` ladder consumes.

### Confidence triage per reflected context
Tag each reflected context, mirroring the DOM `source_sink_flows.confidence` enum, and let it
order the fan-out (record the call in `notes`):
- `confirmed` — breakout chars survive raw in an executable context (fire is near-certain).
- `probable` — context is executable but some chars are encoded (a bypass is plausible).
- `tentative` — reflected but encoded/sanitized, or a non-executable context (`style`/comment).
Route and prioritise `confirmed` > `probable`; treat `tentative` as last. (A structured
`confidence` / `occurrences` field on `reflection` in `xss_context.schema.json` — it exists
today only on `dom.source_sink_flows` — is a clean optional follow-up if you want it typed.)
