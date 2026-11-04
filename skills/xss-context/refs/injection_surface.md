# Injection surface + marker strategy (steps 2–3)

The variants are only as good as the surface this feeder maps. Probe EVERY source,
not just query params — most missed XSS hides in headers, JSON keys, and fragments.

## Sources to probe (one marker per (point, source))

| Source | Where | Notes / routing |
|---|---|---|
| `query` | `?p=MARKER` | classic reflected surface |
| `body` | form fields; **JSON keys and values**; multipart filenames | expand nested JSON; `Content-Type` matters |
| `path` | `/x/MARKER/y`, trailing segment, `.ext` | reflected in breadcrumbs/errors |
| `header` | `Referer`, `User-Agent`, `X-Forwarded-For/Host`, `Origin`, custom `X-*` | often reflected into admin/log views → stored/blind |
| `cookie` | reflected cookie values | |
| `fragment` | `#MARKER` | **never sent to server** → DOM only (route to `xss-dom`) |

## Marker strategy

1. **Mapping marker** — unique, benign, greppable, per (point, source):
   ```
   rs<6-hex>         e.g. rs7f3q2a
   ```
   Benign alnum first so WAFs don't interfere with *surface mapping*.
2. **Encoding canary** — once a point reflects, send a canary with the breakout
   chars to learn what the app encodes/strips (feeds `reflection.encoded`):
   ```
   rs7f3q2a"<'>`      → observe which of  "  <  '  >  `  survive unencoded
   ```
3. **Persistence probe** — after a reflecting/submitting request, re-fetch related
   views (profile, dashboard, admin, listing) and grep for the marker. A marker
   that resurfaces elsewhere ⇒ `persists: true` (stored candidate).
4. **Non-reflecting but accepted** — value accepted, never visibly reflected, but
   processed (async job, email, admin panel) ⇒ route to `xss-blind` with an OOB
   marker (`oob.collaborator` from scope.yaml).

All probing is scope-gated and rate-limited (roe-gate.md). Record every probe in
`reflections.jsonl`: `{point_id, source, param, marker, reflected, where, encoded, persists}`.

---

## Extended arsenal — attacker-controlled & second-order carriers

The source table above finds where input *reflects*. These carriers decide how an
attacker *delivers* it — they turn a passive reflection into a victim-affecting fire.

### Reflected into a RESPONSE HEADER → CRLF / response-splitting → XSS
When a point's value lands in a response header (redirect `Location`, `Set-Cookie`,
`Content-Type`, a custom `X-*`), test whether a raw CR/LF survives — the response-
splitting primitive (owned by `host-header` / `request-smuggling` / `open-redirect`)
becomes an XSS *carrier* when the injected line opens a body:
- Probe ladder: `%0d%0a`, lone `%0a`, double-encoded `%250d%250a`, and unicode/overlong
  `%E5%98%8A%E5%98%8D` (CR/LF via charset decode) — try each; some stacks strip one form, pass another.
- Confirm in two safe steps: (1) inject a benign extra header (`…%0d%0aX-RS:<marker>`) and
  see it echoed → splitting proven; (2) inject a blank line + a minimal body marker, then
  browser-verify the marker *executes* same-origin. Never inject headers that poison a shared
  cache without approval (`cache-poisoning` rules).
- Record on the point: `notes: "value -> response header; CRLF survives -> splitting"`, and
  route `reflected` (often `stored`-like when a cache/proxy replays it).

### Cookie as an attacker-CONTROLLED carrier (not just a source)
A reflected cookie value is only a bug if the attacker can SET the cookie the victim sends.
Note the delivery precondition before routing a `cookie` point:
- cookie-tossing from a sibling/parent domain (a bug on `*.target` sets a cookie scoped to
  the apex), a `Set-Cookie` won from an adjacent / CRLF / self-XSS bug, or a cookie-setting
  endpoint (`?lang=` / `?theme=` persisted to a cookie then reflected).
- With a delivery path, "reflected cookie value" is effectively **persistent / victim-
  affecting** XSS, not self-XSS — route `stored`/`blind` and rate by the viewer reached.

### Second-order header reflection (deepen the `header` source)
`User-Agent` / `Referer` / `X-Forwarded-*` rarely reflect to *you* — they reflect to the
operator: admin dashboards, log/analytics viewers, error consoles, support tooling. Set the
header on the request whose artifact a privileged user later renders → stored/blind cross-
privilege. Point the OOB marker (`oob.collaborator`) at those write-only surfaces.

### XST (Cross-Site Tracing) — legacy footnote
`TRACE`/`TRACK` echo request headers (incl. otherwise `HttpOnly` cookies). Modern browsers
forbid `TRACE` via script and most stacks disable the verb — feasibility-note only; worth a
single probe where an ancient server + a header-echo path coexist, almost never a live bug.
