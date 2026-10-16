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
