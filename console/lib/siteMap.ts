// Site Map builder — turns the real engagement artifacts into a Burp-style host→path
// tree. It renders ONLY what recon actually found (no fabricated HTTP): the union of
//   • content-discovery's content.json routes (path, status, type, methods, params, notes)
//   • host-discovery's host_discovery.json (live_hosts, api_endpoints, web_routes_seen)
//   • the hosts/paths named by the engagement's findings
// Each discovered URL becomes one SiteRoute; findings are linked by host+path so a branch
// can show the worst issue on it. Pure + deterministic so it can be unit-tested and so the
// Site Map page stays a thin view over it.

import type { ContentMap, Finding } from "./types";
import { SEVERITY } from "./theme";
import { isReportable } from "./format";

export type RouteSource = "content" | "host" | "api" | "finding";

/** One discovered URL under a host, merged across every artifact that surfaced it. */
export interface SiteRoute {
  id: string;
  host: string;            // hostname (no port), the tree-root key
  path: string;            // pathname (+ any query), always starts with "/"
  method: string;          // primary verb (first of `methods`, else GET)
  methods: string[];
  status?: number;
  type?: string;
  params: string[];
  note?: string;
  js?: string;
  evidence?: string;       // api_endpoints evidence string
  introspection?: boolean;
  confirmed?: boolean;
  sources: RouteSource[];  // which artifacts named this URL
  findingIds: string[];    // non-composite findings whose asset matches this URL
}

export type NodeKind = "host" | "dir" | "file" | "q";
export interface SiteNode {
  key: string;
  host: string;
  label: string;
  path: string;            // "/" for the host root, else "/a/b"
  kind: NodeKind;
  dir?: boolean;           // path ended in a slash somewhere
  children: SiteNode[];
  routes: SiteRoute[];     // routes landing exactly on this node
  parent: SiteNode | null;
}

export interface SiteMap {
  roots: SiteNode[];
  nodes: Map<string, SiteNode>;
  routes: SiteRoute[];
  paramsDiscovered: string[];
  notableSinks: { category: string; items: string[] }[];
  crawlMethod?: string;
  hostCount: number;
  routeCount: number;
}

/* ------------------------------------------------------------------ helpers */

/** hostname without a port (the key the rest of the console attributes by). */
function hostnameNoPort(h: string): string {
  return (h || "").split("/")[0].split(":")[0].trim().toLowerCase();
}

/** Split a raw target/url/asset token into { host, path }. Tolerates scheme-less
 *  tokens ("pentest-ground.com:5013/graphql") and bare hosts ("api.acme.io"). */
function splitTarget(raw: string): { host: string; path: string | null } | null {
  const t = (raw || "").trim();
  if (!t) return null;
  try {
    const u = new URL(t.includes("://") ? t : "http://" + t);
    const host = hostnameNoPort(u.host);
    if (!host) return null;
    const path = (u.pathname || "/") + (u.search || "");
    return { host, path: path === "/" && !u.search ? "/" : path };
  } catch {
    const host = hostnameNoPort(t);
    return host ? { host, path: null } : null;
  }
}

/** Normalize a route path to a leading-slash pathname+query string. */
function normPath(p: string): string {
  let s = (p || "").trim();
  if (!s) return "/";
  // a full URL in the path field → keep only path+query
  if (/^[a-z]+:\/\//i.test(s)) {
    const st = splitTarget(s);
    if (st?.path) return st.path;
  }
  if (!s.startsWith("/")) s = "/" + s;
  return s;
}

const pathNoQuery = (p: string): string => p.split(/[?#]/)[0] || "/";

/** Every (host, path|null) a finding points at, across a comma/space-joined asset. */
function findingTargets(f: Finding): { host: string; path: string | null }[] {
  return (f.asset || "")
    .split(/[,\s]+/)
    .map(splitTarget)
    .filter((x): x is { host: string; path: string | null } => !!x);
}

/* --------------------------------------------------------------- collection */

interface Raw {
  host: string;
  path: string;
  method?: string;
  methods?: string[];
  status?: number;
  type?: string;
  params?: string[];
  note?: string;
  js?: string;
  evidence?: string;
  introspection?: boolean;
  confirmed?: boolean;
  source: RouteSource;
}

/** Pick the host the content.json routes belong to (they carry only paths). */
function primaryHost(content: ContentMap | undefined, host: any, findings: Finding[]): string {
  const fromContent = content?.target ? hostnameNoPort(content.target) : "";
  if (fromContent) return fromContent;
  const lh = host && Array.isArray(host.live_hosts) ? host.live_hosts : [];
  for (const h of lh) {
    const hv = hostnameNoPort(h?.host || h?.url || "");
    if (hv) return hv;
  }
  for (const f of findings) {
    const t = findingTargets(f)[0];
    if (t) return t.host;
  }
  return "";
}

function collect(content: ContentMap | undefined, host: any, findings: Finding[]): Raw[] {
  const out: Raw[] = [];
  const primary = primaryHost(content, host, findings);

  // content-discovery routes (paths under the primary crawl host)
  for (const r of content?.routes ?? []) {
    if (!r || typeof r.path !== "string") continue;
    const path = normPath(r.path);
    const st = splitTarget(r.path.includes("://") ? r.path : "");
    const hostFor = st?.host || primary;
    if (!hostFor) continue;
    out.push({
      host: hostFor, path,
      methods: Array.isArray(r.methods) ? r.methods : undefined,
      status: typeof r.status === "number" ? r.status : undefined,
      type: r.type, params: Array.isArray(r.params) ? r.params : undefined,
      note: r.note, js: r.js, introspection: r.introspection, source: "content",
    });
  }

  // host-discovery: live hosts (a "/" root each), api_endpoints, web_routes_seen
  if (host) {
    for (const h of Array.isArray(host.live_hosts) ? host.live_hosts : []) {
      const hv = hostnameNoPort(h?.host || h?.url || "");
      if (!hv) continue;
      out.push({ host: hv, path: "/", status: typeof h?.status === "number" ? h.status : undefined, type: "html", note: h?.title, source: "host" });
    }
    for (const e of Array.isArray(host.api_endpoints) ? host.api_endpoints : []) {
      const st = splitTarget(e?.url || "");
      const hostFor = st?.host || (e?.host ? hostnameNoPort(e.host) : "") || primary;
      const path = st?.path || (typeof e?.path === "string" ? normPath(e.path) : null);
      if (!hostFor || !path) continue;
      out.push({
        host: hostFor, path,
        methods: Array.isArray(e?.methods) ? e.methods : undefined,
        type: e?.type, evidence: e?.evidence || e?.notes, confirmed: e?.confirmed === true, source: "api",
      });
    }
    for (const p of Array.isArray(host.web_routes_seen) ? host.web_routes_seen : []) {
      if (typeof p !== "string" || !primary) continue;
      out.push({ host: primary, path: normPath(p), source: "host" });
    }
  }

  // findings' own assets — so every URL an engagement touched shows up
  for (const f of findings) {
    if (f.composite) continue;
    for (const t of findingTargets(f)) {
      if (!t.path) continue; // host-only asset → linked at the host root below, not a new route
      out.push({ host: t.host, path: normPath(t.path), source: "finding" });
    }
  }
  return out;
}

/** Merge raws that share host+path into one SiteRoute (union verbs/params/sources). */
function mergeRoutes(raws: Raw[]): SiteRoute[] {
  const byKey = new Map<string, SiteRoute>();
  const uniq = (a: string[]) => Array.from(new Set(a.filter(Boolean)));
  for (const r of raws) {
    const key = r.host + "\n" + r.path;
    const verbs = (r.methods && r.methods.length ? r.methods : r.method ? [r.method] : []).map((m) => m.toUpperCase());
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, {
        id: "rt-" + byKey.size,
        host: r.host, path: r.path,
        method: verbs[0] || "GET", methods: verbs.length ? uniq(verbs) : ["GET"],
        status: r.status, type: r.type, params: uniq(r.params ?? []),
        note: r.note, js: r.js, evidence: r.evidence, introspection: r.introspection,
        confirmed: r.confirmed, sources: [r.source], findingIds: [],
      });
    } else {
      existing.methods = uniq([...existing.methods, ...verbs]);
      existing.method = existing.methods[0] || "GET";
      if (existing.status == null && r.status != null) existing.status = r.status;
      if (!existing.type && r.type) existing.type = r.type;
      if (r.params?.length) existing.params = uniq([...existing.params, ...r.params]);
      if (!existing.note && r.note) existing.note = r.note;
      if (!existing.js && r.js) existing.js = r.js;
      if (!existing.evidence && r.evidence) existing.evidence = r.evidence;
      if (r.introspection) existing.introspection = true;
      if (r.confirmed) existing.confirmed = true;
      if (!existing.sources.includes(r.source)) existing.sources.push(r.source);
    }
  }
  return Array.from(byKey.values());
}

/** Attach findings to routes (exact host+pathname match) and to host roots (host-level). */
function linkFindings(routes: SiteRoute[], findings: Finding[]): void {
  const byHostPath = new Map<string, SiteRoute[]>();
  const rootByHost = new Map<string, SiteRoute>();
  for (const rt of routes) {
    const k = rt.host + "\n" + pathNoQuery(rt.path);
    const list = byHostPath.get(k);
    if (list) list.push(rt); else byHostPath.set(k, [rt]);
    if (pathNoQuery(rt.path) === "/") rootByHost.set(rt.host, rt);
  }
  for (const f of findings) {
    if (f.composite) continue;
    const hit = new Set<SiteRoute>();
    for (const t of findingTargets(f)) {
      if (t.path) {
        const exact = byHostPath.get(t.host + "\n" + pathNoQuery(t.path));
        if (exact) exact.forEach((rt) => hit.add(rt));
      }
      if (!t.path || pathNoQuery(t.path || "/") === "/") {
        const root = rootByHost.get(t.host);
        if (root) hit.add(root);
      }
    }
    for (const rt of hit) if (!rt.findingIds.includes(f.id)) rt.findingIds.push(f.id);
  }
}

/* ------------------------------------------------------------------- tree */

function insert(nodes: Map<string, SiteNode>, roots: SiteNode[], rt: SiteRoute): void {
  let node = nodes.get(rt.host);
  if (!node) {
    node = { key: rt.host, host: rt.host, label: rt.host, path: "/", kind: "host", children: [], routes: [], parent: null };
    nodes.set(rt.host, node);
    roots.push(node);
  }
  const qi = rt.path.indexOf("?");
  const pathPart = qi < 0 ? rt.path : rt.path.slice(0, qi);
  const query = qi < 0 ? "" : rt.path.slice(qi + 1);
  const segs = pathPart.split("/").filter(Boolean);
  let acc = "";
  for (const s of segs) {
    acc += "/" + s;
    const key = rt.host + acc;
    let child = nodes.get(key);
    if (!child) {
      child = { key, host: rt.host, label: s, path: acc, kind: "file", children: [], routes: [], parent: node };
      nodes.set(key, child);
      node.children.push(child);
    }
    node = child;
  }
  if (segs.length && pathPart.endsWith("/")) node.dir = true;
  if (query) {
    const key = node.key + "?" + query;
    let child = nodes.get(key);
    if (!child) {
      let label = query; try { label = decodeURIComponent(query); } catch { /* keep raw */ }
      child = { key, host: rt.host, label: "?" + label, path: (node.kind === "host" ? "" : node.path) + "?" + query, kind: "q", children: [], routes: [], parent: node };
      nodes.set(key, child);
      node.children.push(child);
    }
    node = child;
  }
  node.routes.push(rt);
}

/* --------------------------------------------------------------- public API */

export function buildSiteMap(content: ContentMap | undefined, host: any, findings: Finding[]): SiteMap {
  const routes = mergeRoutes(collect(content, host, findings));
  linkFindings(routes, findings);

  const nodes = new Map<string, SiteNode>();
  const roots: SiteNode[] = [];
  // stable host order, then stable path order, so the tree doesn't reshuffle per render
  routes.sort((a, b) => a.host.localeCompare(b.host) || a.path.localeCompare(b.path));
  for (const rt of routes) insert(nodes, roots, rt);
  roots.sort((a, b) => a.host.localeCompare(b.host));

  const notableSinks = Object.entries(content?.notable_sinks ?? {})
    .filter(([, v]) => Array.isArray(v) && v.length)
    .map(([category, items]) => ({ category, items: items as string[] }));

  return {
    roots, nodes, routes,
    paramsDiscovered: Array.isArray(content?.params_discovered) ? content!.params_discovered! : [],
    notableSinks,
    crawlMethod: content?.crawl_method,
    hostCount: roots.length,
    routeCount: routes.length,
  };
}

/** Every route at or beneath a node (depth-first). */
export function subtreeRoutes(n: SiteNode, out: SiteRoute[] = []): SiteRoute[] {
  out.push(...n.routes);
  for (const c of n.children) subtreeRoutes(c, out);
  return out;
}

/** Child nodes ordered: real paths first (alpha), query nodes last. */
export function sortedChildren(n: SiteNode): SiteNode[] {
  return [...n.children].sort(
    (a, b) => Number(a.kind === "q") - Number(b.kind === "q") || a.label.localeCompare(b.label),
  );
}

/** The full URL a node represents (best-effort; scheme assumed https). */
export function nodeUrl(n: SiteNode): string {
  if (n.kind === "host") return `https://${n.host}/`;
  return `https://${n.host}${n.path}`;
}

/** Severity rank of the worst non-composite finding on a route (0 = none). */
export function routeSeverityRank(rt: SiteRoute, byId: Map<string, Finding>): number {
  let rank = 0;
  for (const id of rt.findingIds) {
    const f = byId.get(id);
    if (f) rank = Math.max(rank, SEVERITY[f.severity]?.rank ?? 0);
  }
  return rank;
}

/** Does a route carry at least one reportable finding? */
export function routeHasIssue(rt: SiteRoute, byId: Map<string, Finding>): boolean {
  return rt.findingIds.some((id) => { const f = byId.get(id); return !!f && isReportable(f); });
}
