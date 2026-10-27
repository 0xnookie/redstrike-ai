# Where stored values render back (steps 2, 4)

Stored XSS lives in the gap between WHERE input is stored and WHERE it renders — often a
different endpoint, viewed by a different user. Map that gap. For each candidate, find every
surface the value resurfaces on, and WHO views it (the viewer privilege is the impact).

## Find every render surface in the client bundle — don't trust the submission page
A stored value often renders on a **different route/component of the SAME app** than the form that
submits it (SPA: entered in a profile modal, rendered on a dashboard card). Testing only the
submission page is a false negative. Resolve the sink statically before firing payloads:
- Grep the client bundles for the stored field name AND its JSON key, and for every write sink
  (`innerHTML`, `insertAdjacentHTML`, `.html(`, `dangerouslySetInnerHTML`, `document.write`).
  The sink type decides execution: `innerHTML`/`insertAdjacentHTML` run event-handler/auto-exec
  vectors but **NOT** a top-level `<script>`; `textContent`/`.setAttribute`/`dataset`/framework
  interpolation are safe — downgrade to HTML-injection or no-finding.
- A field can render on several surfaces with different sinks/contexts — enumerate ALL, test each.
- **Normalizers can strip your payload before it is stored.** Geocoders, valid-ID/record lookups,
  and format validators (address / phone / IBAN / name) canonicalize input and discard anything
  extra — the search box echoes your payload but the stored value is the clean canonical form.
  Inject past the normalizer (craft the normalized object the save endpoint consumes directly, or
  use a value that does not resolve) and confirm the RAW payload is what gets persisted.

## Common store → render pairs

| Stored via | Renders on | Typical viewer | Notes |
|---|---|---|---|
| profile: display name / bio / avatar-url | profile page, @mentions, member lists, comment author | other users, admins | classic; check mention/notification rendering |
| comment / review / post | thread view, moderation queue | all viewers, moderators | moderation queue = admin viewer (high impact) |
| support ticket / contact form | **agent/admin console** | staff only | tester often can't see → `xss-blind` + OOB |
| username / email / company | admin user table, audit log, invoices | admins | second-order |
| `User-Agent` / `Referer` / `X-Forwarded-For` | **admin analytics / log viewer** | admins | header-sourced stored XSS; pair with xss-context header probing |
| filename / upload metadata | file listing, preview, export | other users, admins | also check EXIF/metadata |
| message / chat / DM | recipient's view | a specific other user | targeted |
| organization / team settings | every member's view | whole tenant | multi-tenant blast radius |
| webhook / integration config | config/preview pages, exported reports | admins | |
| data exported to PDF / CSV / report | report viewer, email | admins, external | render context differs (PDF engine, email client) |

## Viewer privilege → route & rate

- renders only in the **submitter's own** view → likely self/reflected, downgrade (verify.md).
- renders to **other users** → stored, standard impact.
- renders to **admins/staff** → stored, high impact (privileged victim) — and often the surface
  the tester cannot reach directly ⇒ confirm via **OOB canary** and consider `xss-blind` handoff.
- renders to the **whole tenant** → highest blast radius; benign payload + approval + cleanup.

Record each confirmed pair in `render_map.json`:
`{candidate_id, store_endpoint, render_surface, viewer: same|other|admin|anon, reachable_by_tester: bool}`.
