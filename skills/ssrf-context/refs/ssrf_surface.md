# SSRF surface + benign fetch confirmation (steps 1–3)
# Find where the SERVER fetches a URL you influence. Confirm with a benign OOB URL first.
# Record in behavior_probes.jsonl: {sink_id, param, oob_hit, reflects_response, redirects, protocols, allowlist}.

## Where fetch sinks hide
- **Params:** `url`, `uri`, `link`, `src`, `dest`, `target`, `redirect`, `callback`, `webhook`,
  `feed`, `rss`, `import`, `source`, `path`, `domain`, `host`, `proxy`, `fetch`, `load`, `image`, `avatar`.
- **Features:** import-from-URL, webhook/callback config, image/PDF/thumbnail generation, link/URL
  preview (chat, markdown), SSO/OIDC/SAML metadata URL, PDF-from-HTML, "test connection" / health
  checks, document converters, RSS/feed readers, avatar-from-URL.
- **Formats:** a URL inside XML (→ also XXE-SSRF), JSON fields, SVG `<image href>`, PDF, Office docs.

## Confirm a server-side fetch (benign)
```
# point the sink at your OOB host; a hit from the TARGET's egress IP proves server-side fetch
curl -s "https://TARGET/api/fetch?url=http://OOB_TOKEN.oob.example/"
```
A DNS/HTTP interaction from the server (not your browser) = SSRF sink. Note the egress IP + UA.

## Characterize (feeds variant_hint)
- **Response reflected** (status/body/length differs by target) → `inband`.
- **No reflection, only OOB** → `blind`.
- **Looks like it could reach link-local / cloud metadata** → route `cloud` — but **the feeder does NOT
  probe `169.254.169.254` / loopback / RFC1918 itself** (that is exploitation, `ssrf-cloud`'s job, under
  approval; see §Safety). Classify by the sink's shape (server-side fetcher, follows redirects, no egress
  allowlist, cloud-hosted) from the EXTERNAL benign-OOB behaviour you already observed, and set
  `variant_hint: cloud` so `ssrf-cloud` runs the metadata probe later.
- Record: follows redirects? (301→internal bypass), protocols (`http`,`https`,`gopher`,`file`,`dict`),
  allowlist style (host suffix? scheme? DNS re-bind window?).

> **Feeder scope boundary (benign envelope).** This feeder confirms a sink fetches an **external benign
> OOB URL** (`http://TOKEN.oob.example/`) and records its behaviour — nothing more. Aiming a probe at an
> **internal/metadata target** (`169.254.0.0/16`, `127.0.0.1`/`localhost`, RFC1918) is **exploitation**,
> OUT of feeder scope, and belongs to `ssrf-cloud` / `ssrf-inband` / `ssrf-blind` under their approval
> gate. The feeder only *routes* (sets `variant_hint`) and *lists* candidate internal targets for the
> variant to use — it never fires at them.
