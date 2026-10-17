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

---
## Extended arsenal — expanded fingerprint matrix (CNAME pattern → signature → claimable)

Net-new services + the CNAME-target dimension. `edge/verify` = provider added custom-domain ownership
checks, so a signature match is a LEAD — confirm the claim flow before rating.

| Service | CNAME target pattern | Dangling-state signature | Claimable? |
|---|---|---|---|
| AWS CloudFront | `*.cloudfront.net` | `ViewerCertificateException` / 403 no-origin | rarely (alias on a free dist) |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` | NXDOMAIN on env host | yes (re-create env name/region) |
| Azure (variants) | `*.azurewebsites.net` / `*.cloudapp.azure.com` / `*.blob.core.windows.net` / `*.trafficmanager.net` | "Web Site not found" / NXDOMAIN | yes (re-create the resource name) |
| GCP App Engine | `ghs.googlehosted.com` / `*.appspot.com` | `404 … requested URL was not found` | edge (domain-mapping verify) |
| Firebase | `*.web.app` / `*.firebaseapp.com` | "Site Not Found" | edge |
| Bitbucket | `*.bitbucket.io` | `Repository not found` | yes |
| WordPress.com | `*.wordpress.com` | `Do you want to register *.wordpress.com?` | edge |
| Ghost | `*.ghost.io` | "Site unavailable" / "Failed to resolve DNS path" | yes |
| Help Scout | `*.helpscoutdocs.com` | "No settings were found for this company" | yes |
| Cargo Collective | `*.cargocollective.com` | `404 Not Found` | yes |
| Webflow | `proxy-ssl.webflow.com` | "The page you are looking for doesn't exist…" | edge |
| Strikingly | `*.s.strikinglydns.com` | `PAGE NOT FOUND.` | yes |
| Tilda | `*.tilda.ws` | "Please renew your subscription" | edge |
| Smartling | `*.smartling.com` | "Domain is not configured" | edge |
| Agile CRM | `*.agilecrm.com` | "Sorry, this page is no longer available." | yes |
| Short.io | custom short-domain | "Link does not exist" | yes |
| Statuspage | `*.statuspage.io` | hosted-status not-found | edge |
| Vercel | `cname.vercel-dns.com` | "The deployment could not be found" / 404 | edge |

---
## Extended arsenal — NS / MX / dangling-A & wildcard variants

- **Dangling NS (highest impact):** parent delegates to a zone/nameserver no longer live at the provider.
```
dig +norecurse NS sub.TARGET.com @<parent-ns>     # read the delegation
dig SOA sub.TARGET.com @<delegated-ns>            # REFUSED/SERVFAIL / no-AA / no-SOA = lead
```
  If the provider lets a new account create that zone → full DNS control of the subtree. Creating the zone can disrupt prod DNS — confirm ONLY with authorization.
- **Expired-registration domain** the org still CNAMEs/NSes to → re-register the apex (domain takeover).
- **MX takeover:** subdomain MX → deprovisioned mail tenant → attacker receives/sends mail for it; catalogue (proving needs account creation → authorize first).
- **Dangling A/AAAA:** record → released cloud IP; same-provider/region re-allocation can land it → cross-check passive-DNS history.
- **Wildcard caveat:** a `*.TARGET` CNAME to a third party yields infinite "matches" — confirm the record is explicit, not wildcard, before calling takeover.

---
## Extended arsenal — detection tooling

```
nuclei -l subs.txt -tags takeover -o takeovers.txt        # maintained CNAME+body signature set
dnsreaper file --filename subs.txt                        # per-service signature engine, low-FP
subjack -w subs.txt -ssl -c fingerprints.json -o sj.txt   # classic CNAME+fingerprint
subzy run --targets subs.txt                              # alt fingerprint engine
tko-subs -domains=subs.txt                                # CNAME→provider→claimable check
```
Cross-check any single-tool hit with a manual `dnsx -cname -a -ns` + `httpx` fetch before rating (tools carry stale signatures). Candidates feed in from host-discovery / js-analysis subdomain lists.

---
## Extended arsenal — benign claim-verification protocol

- **Proof = control, not content.** If authorized to claim: register the resource and serve a single harmless marker (a random token at `/<engagement-id>.txt`) reachable by the test request only — NEVER real site content, redirects, forms, or data capture against live users.
- **No claim authorization → stop at evidence:** the dangling chain (`dnsx`), the unclaimed-state fingerprint (`httpx` body), and proof the name is registrable (free bucket/app/repo name, open claim page). Document → remediation.
- **Clean up:** de-provision the marker + release the claimed resource at engagement end (cleanup.md); record the claim in the report.
- **Rule out false positives:** client-owned resource, generic/parked 404 with no claimable backend, wildcard record, provider that patched silent takeover.
