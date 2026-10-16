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
