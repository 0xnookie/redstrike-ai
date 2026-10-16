# Write-only / unseen surfaces for blind XSS (steps 1, 4)
# Blind XSS lives where YOU inject but SOMEONE ELSE (usually staff/an automated renderer) views.
# These are exactly the surfaces xss-stored flagged `reachable_by_tester: false`, plus header sinks.
# For each, note the likely VIEWER (impact) and the likely RENDERER (payload family).

| Inject at | Likely viewer | Likely renderer | Notes |
|---|---|---|---|
| contact / support / feedback form | support agent console | web app | classic blind XSS target |
| user-agent / referer / x-forwarded-* headers | admin analytics / log viewer | web log UI | header-sourced; inject on normal requests |
| profile fields (name, bio, company, website) | admins, moderators | web app | second-order; fires in admin user table |
| uploaded filename / document metadata (EXIF, author) | file browser, preview, export | web / office / PDF | test metadata, not just content |
| order / invoice / address fields | billing/admin, invoice PDF | web + PDF engine | PDF renderers run JS in some engines |
| API / integration fields, webhook URLs & payloads | internal dashboards | web | JSON fields surfaced in admin UIs |
| chat / ticket / comment to staff | agent/moderator | web | |
| error-triggering input | error-monitoring dashboard (Sentry-like) | web | exceptions rendered to devs |
| email-bound fields (name shown in notification) | recipient's mail client | email HTML | different context; limited JS, but test |

## Approach
- Inject a token-tagged beacon into EVERY field/header a surface accepts, on otherwise-normal requests.
- One unique token per (surface, field) so a callback is attributable (verify.md requires this).
- Many fires are delayed (a human opens the ticket later) — keep the listener up for the window.
- Prefer surfaces with privileged viewers (admin/staff) — higher impact and the whole point of blind.
