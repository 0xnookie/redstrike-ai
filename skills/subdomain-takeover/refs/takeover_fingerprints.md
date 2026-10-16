# Subdomain takeover service fingerprints (step 3)
# Match the dangling target's response against a KNOWN claimable-state signature. The authoritative,
# maintained set is nuclei's http/takeovers templates + the can-i-take-over-xyz project — sync those.
# This is a quick-reference seed. Record in takeover_candidates.jsonl:
# {subdomain, record_type, target, service, fingerprint, claimable}.

| Service | Dangling-state fingerprint | Claimable? |
|---|---|---|
| AWS S3 | `NoSuchBucket` / "The specified bucket does not exist" | yes (register bucket name) |
| GitHub Pages | "There isn't a GitHub Pages site here." | yes (create repo + CNAME) |
| Heroku | "No such app" / default Heroku 404 | yes (claim app name) |
| Fastly | "Fastly error: unknown domain" | often (add to a Fastly service) |
| Azure (cloudapp/trafficmanager/azurewebsites) | default 404 / "Web Site not found" | yes |
| Shopify | "Sorry, this shop is currently unavailable." | sometimes (verify) |
| Zendesk | "Help Center Closed" | sometimes |
| Surge.sh | "project not found" | yes |
| Netlify | "Not Found - Request ID" default | sometimes |
| Pantheon / Readthedocs / Tumblr / Unbounce | service-specific "not found" strings | varies |

## Method
1. For each subdomain, resolve the CNAME/A/NS chain (`dnsx -cname -a -ns`).
2. If the final target is a third-party service, fetch it (`httpx`) and match the fingerprint.
3. A fingerprint match ⇒ CANDIDATE. Confirm the resource is registrable (service's claim flow).
4. NS takeovers (dangling NS delegation) are higher-impact — flag separately.

Prefer `nuclei -t http/takeovers` for the up-to-date signature set; this table is for triage/offline.
