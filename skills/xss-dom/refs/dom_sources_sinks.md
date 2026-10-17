# DOM XSS taint catalog + gadgets (steps 2–3)
# The feeder (xss_context.json dom.*) hands you candidate flows; this ref is for GATHERING the
# gadgets it couldn't, by reading js/beautified/ + live DOM. Record flows in taint_flows.json:
# {id, source, path:[fn,...], sink, controllable, origin_checked?, notes}.

## Sources (attacker-controllable)
| Source | Control | Delivery |
|---|---|---|
| `location.hash` | full | crafted URL `#...` (never sent to server) |
| `location.search` / `location.href` / `location.pathname` | full | crafted URL |
| `document.URL` / `document.documentURI` / `document.baseURI` | full | crafted URL |
| `document.referrer` | full | link from attacker page |
| `window.name` | full | set on attacker page, then navigate |
| `postMessage` (`event.data`) | full **iff** handler skips/misvalidates `event.origin` | attacker page/iframe |
| `localStorage` / `sessionStorage` | conditional | needs a set path (often another bug) |
| `document.cookie` | conditional | cookie-set vector |
| `history.state` | conditional | `pushState` flows |

## Sinks (dangerous) — mirror js-analysis/refs/dangerous_sinks.yaml
- **HTML:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`, `$(...).html/append/prepend/after/before`, `Range.createContextualFragment`, `DOMParser.parseFromString`
- **Code exec:** `eval`, `new Function`, `setTimeout`/`setInterval`/`setImmediate` (string arg), `execScript`
- **Navigation / scheme:** `location`, `location.href/assign/replace`, `window.open`, `a.href`, `iframe.src`, `script.src`, `form.action` (→ `javascript:`)
- **Attribute:** `setAttribute` (flag `on*`, `href`, `src`, `srcdoc`, `formaction`), `iframe.srcdoc`

## Gadgets to gather (the part a flow scanner misses)
- **postMessage without origin check:** `window.addEventListener('message', h)` where `h` uses
  `event.data` in a sink and never checks `event.origin` (or checks with `indexOf`/`startsWith`
  that a subdomain/attacker string satisfies).
- **Prototype pollution → DOM XSS:** a client-side merge/extend of attacker input
  (`?__proto__[x]=`, JSON merge) polluting a property later used as a sink (e.g. config `src`,
  template, `innerHTML` default). Known sink gadgets in jQuery `$.extend`, lodash `merge/set`,
  and many config loaders.
- **jQuery classics:** `$(location.hash)` / `$(userInput)` → HTML injection (esp. < 3.5);
  `$.parseHTML`, `.html(userInput)`.
- **Client-side template injection:** AngularJS (`ng-app` sandbox-escape sinks), Vue `v-html`,
  Handlebars/`_.template` compiled from user input, `*[innerHTML]` bindings.
- **Open-redirect→XSS:** client-set `location` from a source allowing `javascript:`.

Each gadget that reaches a sink from a controllable source becomes a `taint_flows.json` entry and
a `dom_candidates.json` candidate for the exploitation phase.

---

## Extended arsenal — additional sinks (beyond the core list)
| Sink | Class | Note |
|---|---|---|
| `Element.setHTMLUnsafe` / `ShadowRoot.setHTMLUnsafe` | HTML (DSD) | parses declarative shadow roots; plain `innerHTML` does NOT |
| `document.implementation.createHTMLDocument` | HTML | off-document parse, often fed to a later adopt/import |
| `script.src = x; head.append(script)` | Navigation/scheme | tainted script URL → load |
| template-literal `el.innerHTML = \`…${raw}…\`` | HTML | one field sanitized, another interpolated raw |
| markdown→HTML render (`marked`/renderer) | HTML | source text re-emitted as HTML (sanitize-order bugs) |
| CSS `<style>` / stylesheet / `el.style` injection | scriptless exfil | attribute-selector / `@import` / `@font-face` leak |
| `new RegExp(src)` / `setImmediate(str)` / `requestFileSystem` | code/DoS | lesser-known string-eval-adjacent sinks |
| `getHTML({serializableShadowRoots})` / `cloneNode` | recon | exposes shadow content after XSS |

Trusted Types note: TT (`require-trusted-types-for 'script'`) guards the HTML/code-exec/`script.src`
string sinks — it does NOT cover navigation/scheme sinks (`location`, `a.href`=`javascript:`), CSS
injection, or a gadget that is itself the trusted caller (script gadgets).

---

## Extended arsenal — additional sources / gadget surfaces to gather
| Source / gadget | Control | Where it bites |
|---|---|---|
| DOM-clobbered named property (`window.<id>`, `document.<name>`, HTMLCollection member) | markup-only | `(window.cfg||{}).url`, `document.cookie`, `getElementById` result |
| `element.dataset.*` / `[data-*]` read by a loader (script gadget) | markup-only | framework/plugin reads attr → sink |
| `querySelector*`/`getElement*`/XPath read of attacker-influenced attr | conditional | gadget selects an injected node, trusts its attr |
| declarative shadow root (`<template shadowrootmode>`) via `setHTMLUnsafe` | full (if sink reached) | shadow subtree with `on*`/slot gadget |
| sanitizer live-DOM return (`RETURN_DOM(_FRAGMENT)`) | conditional | DSD subtree survives, re-arms on append |
| automation-seeded `localStorage`/cookie (bot presets before navigating) | conditional | CTF/headless-bot flows |

Extra gadget classes to flag in `gadgets.md`: DOM clobbering (id/name collisions overriding globals);
script gadgets (markup read by a framework → sink, bypasses sanitizer + Trusted Types); mXSS reparse
(sanitizer tree ≠ re-parsed live tree, SVG/MathML namespace confusion); postMessage→`location` with a
substring (`http:`) check beaten by `javascript:…//http:`; SOME callback (JSONP `opener.<method>`).
