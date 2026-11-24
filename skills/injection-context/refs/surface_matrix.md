# Injection surface matrix — replay the SAME benign canary on EVERY carrier before a negative

# A value reaches an interpreter through many carriers, not just the URL query. A class "clear" that only
# tried ONE carrier is a RECALL GAP, not a clean negative. Discipline: pick the class's benign canary
# (SSTI `{{7*7}}`->49, cmd-injection metachar reaction, a deserializer marker — see `injection_payloads.md`)
# and replay THAT SAME canary across EVERY carrier the point exposes BEFORE recording the class negative/clear.
# Carriers map 1:1 to the `kind` field on `js-analysis` `findings/params.jsonl`, so the carrier list is the
# enumerated attack surface — not a guess.

## DISCIPLINE RULE (depth-substance for a "clear")
- One canary, every carrier. The proof of a negative is "the canary was tried on each exposed carrier and
  none evaluated", NOT "the query string looked clean".
- Carriers come from `js-analysis` `findings/params.jsonl` (`kind`) + `findings/endpoints.jsonl` (path/route
  positions). If the param surface is thin, mine more first (`parameter-optimization`) — an exhausted single
  carrier is not an exhausted surface.
- Same param name often rides >1 carrier (a value read from query OR cookie OR header). Replay on each; a
  server that trusts one carrier over another is exactly the bug.
- Keep it benign: the canary is the detection probe only (arithmetic / metachar reaction / marker
  acceptance), attributable via `TOKEN.oob.example` where blind. No exec here — that's the gated variants.

## The 7 carriers (→ `params.jsonl` `kind`)
| carrier | `params.jsonl` `kind` | where it lives on the wire | canary placement |
|---|---|---|---|
| URL query | `query` | `?name=CANARY` | query string value |
| form body | `form` | `application/x-www-form-urlencoded` / `multipart` field | POST/PUT body field |
| JSON body | `body` | `application/json` request body | string/number value in the JSON |
| cookie | `cookie` | `Cookie: name=CANARY` | cookie value |
| header(s) | `header` | request header value | custom + forwarding/UA/Referer headers |
| path segment | — (route, see `endpoints.jsonl`) | `/api/x/CANARY/...` | a path position the route reads |
| stored / data-attr | `storage` · `data-attr` | local/session storage key, `data-*` attribute | value re-read + rendered later |

Note `path segment` has NO `params.jsonl` `kind` — it is a URL path position, so pull those from
`findings/endpoints.jsonl` (numeric/uuid-ish segments the route parses) and route-table params. Treat it as a
first-class carrier even though it is not in the `kind` vocabulary.

## Commonly MISSED carriers (check these explicitly)
- **JSON body** — an app that rejects a query param may happily evaluate the same value posted as JSON; the
  parser and the sink differ. Re-send every candidate as a JSON value, not just form-encoded.
- **Headers** — `User-Agent` / `Referer` / `X-Forwarded-*` / `X-Original-URL` land in logs, templated error
  pages, and server-side fetches; they are injectable and almost always skipped.
- **Cookies** — values deserialized or templated server-side (session blobs, preference cookies) are a classic
  deser/SSTI carrier that query-only sweeps never touch.
- **Path segment** — a value interpolated from the route (not a `?param`) reaches template/command sinks and
  is invisible to param-only enumeration.
- **Stored / `data-*`** — a canary written once (storage key, `data-*` attribute) that is re-read and rendered
  on a LATER request is a stored-injection carrier; prove store-then-render, not just the write.

## Procedure
1. Build the carrier set for the point from `params.jsonl` (`kind`) + `endpoints.jsonl` (path positions).
2. Replay the class's benign canary on EACH carrier (same value, swap only the carrier).
3. Record per-carrier outcome (evaluated / reflected-only / rejected). A class is negative ONLY when every
   exposed carrier was tried and none evaluated; log that in `probes.jsonl` / `summary.md`.
4. Any carrier that evaluates → route to the variant (`ssti` / `command-injection` / `deserialization`) with
   the winning carrier recorded, so the executor proves it benignly on that exact carrier.
