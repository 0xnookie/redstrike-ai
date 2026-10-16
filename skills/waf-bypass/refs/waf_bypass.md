# WAF / filter bypass technique library
# Authorized, in-scope app only. Probe with BENIGN canaries. Never attack the WAF vendor/another tenant. Not a DoS.

## 1. Fingerprint the WAF/CDN
```
wafw00f https://TARGET        identYwaf
```
- Headers: `Server`, `X-CDN: Incapsula`, `X-Sucuri-ID`, `fastly-debug-*`, `cf-ray` (Cloudflare), `x-amzn-*`.
- Cookies: `__cf_bm`/`cf_clearance`/`cf_chl_*` (Cloudflare), `AWSALB`/`AWSALBCORS`/`AWSELB` (AWS ALB),
  `incap_ses`/`visid_incap` (Imperva), `ak_bmsc` (Akamai).
- Challenge pages / JS objects (`_cf_chl_opt`), route probes (`/cdn-cgi/`), block-page signatures.
- Transport: JA3/JA4 TLS fingerprint, HTTP/2–3 negotiation differences.

## 2. Confirm the block (baseline)
A benign request returns 200; the agent's payload returns 403/406/429 or a challenge. Find the MINIMAL
transform that flips the payload back to a normal response with a benign canary — don't burn exploit strength.

## 3. Payload-level evasion (by the blocked vuln-class)
- **SQLi:** case (`SeLeCt`), inline comments (`UN/**/ION`), whitespace swaps (`%09 %0a %0c %a0 ++`), hex
  (`0x61`), `CHAR()`/`CONCAT`/`||`, numeric rewrites (`1-0`, `1+0`), double-URL-encode, JSON-operator injection.
- **XSS:** context-specific, mutation XSS (parser quirks, `noscript`), alt tags/events (`svg`, `details/ontoggle`),
  `atob`+`eval`, bracket property access, `\u` escapes, entity-encoded `javascript:`, `data:` URIs, CSS vectors,
  polyglots, CSP gadgets (JSONP, DOM clobbering, allowed-origin).
- **Command/SSTI/path:** encoding + separators + wrappers (hand confirmation to that agent).

## 4. HTTP manipulation
- Method case / whitespace (`get`, leading tab before method).
- Spoof-origin headers: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `X-Client-IP`, `Client-IP`,
  `Forwarded`, `X-Originating-IP`.
- Duplicate headers / conflicting `Content-Encoding`; HTTP parameter pollution (`?id=a&id=b`) — see
  `parameter-pollution`; CRLF/line-folding; oversized body; multipart boundary + mixed `Content-Type`
  (put the payload in a low-weight field like multipart `filename`).

## 5. Transport / origin
- **TLS/JA3 alignment**: present a browser-like JA3 (uTLS/tls-client/curl-impersonate) so the fingerprint
  doesn't flag automation.
- **HTTP/2 / HTTP/3**: `curl --http2` / `--http3`; `:authority` vs SNI mismatch; test whether the WAF
  inspects HTTP/2 the same as HTTP/1.
- **Origin discovery** (bypass the CDN entirely): Shodan/Censys, `CloudFlair`, historical DNS
  (SecurityTrails), `Alt-Svc` leakage, then a direct request to the origin IP with a spoofed `Host`.
  **Scope-check any origin IP before using it.**
- **SNI**: `openssl s_client -servername`, `curl --connect-to`, domain fronting (CDN-dependent).

## 6. GraphQL / ML-WAF
- GraphQL: deep alias nesting, batched ops, renamed fields, upload-scalar variants (`graphql-cop`, `InQL`).
- ML/semantic WAFs: semantic rewrites, noise-token padding, Unicode homoglyphs, mixed SQLi/XSS syntax,
  payload in low-weight fields; iterate from the WAF's own feedback.

## Do NOT (DoS — catalogued for awareness only)
Rapid Reset (CVE-2023-44487), CONTINUATION flood, connection-pool exhaustion, IP-fragmentation floods —
**never fire these**; note them for the report if relevant.

## Hand-back
Write `waf_profile.json` = `{waf, evidence, transforms_tried:[{transform, canary, passed}], origin_ip?}`
and `bypass_notes.md` = the specific transform(s) the calling vuln agent should wrap its payloads in.
