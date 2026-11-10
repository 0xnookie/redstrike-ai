// Subdomain-map data layer.
//
// Adapts the REAL engagement recon surface (the notebook's recon_intel.subdomains,
// plus host-discovery assets/services and the findings) into the flat record shape the
// <SubdomainMap> mind-map engine consumes. Pure + framework-agnostic: no DOM, no React.
//
// A record mirrors the dashboard's host record: a host under a root domain, bucketed by
// HTTP status and by network, carrying its source + resolved address + worst finding.

import type { Notebook, Asset, Service, Finding, Engagement, Severity } from "./types";
import { isReportable, assetHosts } from "./format";
import { SEVERITY } from "./theme";

export type MMRecord = {
  host: string;
  rel: string;            // label relative to the root domain ("@" when host === root)
  dom: string;            // registrable root this host hangs under
  net: string;            // colo | cloud | cdn | vendor | priv | none  (derived from the address)
  http: number | null;    // HTTP status observed, or null when it never answered
  st: string;             // live | redirect | auth | error | takeover | dead | skip
  out: boolean;           // out of scope
  src: string;            // how it was found (host-discovery, CT logs, …)
  ip: string;             // resolves_to (A record / CNAME target), or ""
  seen?: number;          // hours since first seen (omitted — no per-host timestamps yet)
  note?: string;
  findings?: { n: number; sev: Severity };
};

export interface SubdomainData {
  domains: string[];
  rootDomain: string;
  records: MMRecord[];
}

const isDottedQuad = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

/** Bucket an address into a coarse network class (the "By network" grouping). */
function netOf(ip: string): string {
  if (!ip) return "none";
  if (isDottedQuad(ip)) {
    if (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return "priv";
    return "colo";
  }
  return "vendor"; // a CNAME / hostname target
}

/** Map an HTTP status (+ scope) to a status bucket — mirrors the dashboard's classifier. */
function statusBucket(http: number | null, scope: string, out: boolean): string {
  if (scope === "takeover") return "takeover";
  if (http == null) return out ? "skip" : "dead";
  if (http < 300) return "live";
  if (http < 400) return "redirect";
  if (http === 401 || http === 403) return "auth";
  return "error";
}

/** Longest in-scope apex a host sits under; else its last two labels. */
function apexFor(host: string, scopeApexes: string[]): string {
  let best = "";
  for (const a of scopeApexes) {
    if ((host === a || host.endsWith("." + a)) && a.length > best.length) best = a;
  }
  if (best) return best;
  const parts = host.split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : host;
}

/** Worst reportable finding + count per host, for the node finding-badge. */
function findingsByHost(findings: Finding[]): Map<string, { n: number; sev: Severity }> {
  const m = new Map<string, { n: number; sev: Severity }>();
  for (const f of findings) {
    if (f.composite || !isReportable(f)) continue;
    for (const host of assetHosts(f.asset)) {
      const cur = m.get(host);
      if (!cur) m.set(host, { n: 1, sev: f.severity });
      else {
        cur.n += 1;
        if (SEVERITY[f.severity].rank > SEVERITY[cur.sev].rank) cur.sev = f.severity;
      }
    }
  }
  return m;
}

export function buildSubdomainData(
  notebook: Notebook | undefined,
  assets: Asset[],
  services: Service[],
  findings: Finding[],
  eng: Engagement,
): SubdomainData {
  const scopeApexes = ((eng && eng.in_scope && eng.in_scope.domains) || [])
    .map((d) => d.replace(/^\*\./, "").replace(/^\./, "").trim().toLowerCase())
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);

  // resolved address per host from host-discovery services (fills ip when the notebook lacks it)
  const ipByHost = new Map<string, string>();
  for (const s of services) if (s.ip && s.host && !ipByHost.has(s.host)) ipByHost.set(s.host, s.ip);

  const fByHost = findingsByHost(findings);
  const byHost = new Map<string, MMRecord>();

  const add = (rawHost: string, http: number | null, scope: string, src: string, ip: string, note?: string) => {
    const host = (rawHost || "").trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    if (!host || byHost.has(host)) return; // first writer (notebook) wins
    const resolved = ip || ipByHost.get(host) || "";
    const dom = apexFor(host, scopeApexes);
    const rel = host === dom ? "@" : host.endsWith("." + dom) ? host.slice(0, -(dom.length + 1)) : host;
    const out = scope === "out";
    const rec: MMRecord = {
      host, rel, dom,
      net: netOf(resolved),
      http,
      st: statusBucket(http, scope, out),
      out,
      src: src || "recon",
      ip: resolved,
      note: note || undefined,
    };
    const fi = fByHost.get(host);
    if (fi) rec.findings = fi;
    byHost.set(host, rec);
  };

  // (a) notebook recon_intel.subdomains — the richest, hand-triaged source
  const subs = (notebook && notebook.recon_intel && notebook.recon_intel.subdomains) || [];
  for (const s of subs) {
    add(
      s.host,
      typeof s.http_status === "number" ? s.http_status : null,
      s.scope || "in",
      s.source || "recon",
      s.resolves_to || "",
      s.note,
    );
  }
  // (b) host-discovery assets not already present (adds hosts the notebook didn't carry)
  for (const a of assets) {
    if (a.kind !== "subdomain" && a.kind !== "ip" && a.kind !== "domain") continue;
    const note = a.note || (a.tech && a.tech.length ? a.tech.join(" · ") : a.title || a.server);
    add(a.value, typeof a.status === "number" ? a.status : null, a.scope === "out" ? "out" : "in", a.server || "host-discovery", "", note);
  }

  const counts = new Map<string, number>();
  for (const r of byHost.values()) counts.set(r.dom, (counts.get(r.dom) || 0) + 1);
  const domains = Array.from(counts.keys()).sort();

  let rootDomain = domains[0] || scopeApexes[0] || (eng && eng.target) || "target";
  let best = -1;
  for (const [d, c] of counts) if (c > best) { best = c; rootDomain = d; }
  // tie → prefer the primary scope apex when it holds the most hosts
  if (scopeApexes.length && counts.get(scopeApexes[0]) === best) rootDomain = scopeApexes[0];

  return { domains, rootDomain, records: Array.from(byHost.values()) };
}
