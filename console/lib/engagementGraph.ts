// Engagement graph builder — unions the engagement's recon + findings + chains into ONE
// connected, explorable graph: scope → host → (service · route) → finding → (chain · agent).
// It draws ONLY edges that already exist in the data (no fabricated links):
//   • scope → host        the in-scope target and every discovered host/subdomain/ip
//   • host  → service     open ports/services from host-discovery
//   • host  → route       discovered endpoints (content.json + host_discovery + proxy history)
//   • route → finding     a finding whose asset matches that endpoint (siteMap host+path link)
//   • host  → finding     a host-level finding with no endpoint match
//   • finding → chain     an attack chain that composes this finding (steps[].finding_id)
//   • finding → agent     the executor skill that produced the finding (review.reviewer)
// Pure + deterministic (layout rows computed here, viewport-independent) so it can be unit-
// tested and so the view stays a thin renderer over it. Reuses buildSiteMap for the
// route↔finding linking rather than re-deriving it.

import type { Asset, AttackChain, ContentMap, Finding, HttpHistory, Service, Severity } from "./types";
import { SEVERITY } from "./theme";
import { assetHosts, hostOf } from "./format";
import { buildSiteMap, type SiteRoute } from "./siteMap";

export type GNodeKind = "scope" | "host" | "service" | "route" | "finding" | "chain" | "agent";
export type GEdgeRel = "scope" | "surface" | "finding" | "chain" | "agent";

/** Layer index per kind — the graph reads left→right along this spine. */
export const KIND_COL: Record<GNodeKind, number> = {
  scope: 0, host: 1, service: 2, route: 2, finding: 3, chain: 4, agent: 4,
};

export interface GNode {
  id: string;
  kind: GNodeKind;
  label: string;
  sub?: string;
  col: number;        // layer (KIND_COL)
  row: number;        // vertical slot (float), viewport-independent
  host?: string;      // owning hostname, for grouping/focus
  sevRank: number;    // worst finding severity touching this node (0 = none)
  severity?: Severity;// a finding node's own severity
  findingId?: string; // → open the finding drawer
  hostName?: string;  // → open the host drawer
  agentSlug?: string;
  meta?: Record<string, string | number | boolean | undefined>;
}
export interface GEdge { id: string; source: string; target: string; rel: GEdgeRel; }

export interface EngagementGraph {
  nodes: GNode[];
  edges: GEdge[];
  stats: Record<GNodeKind, number> & { worstSev: number; rows: number };
}

export interface EngagementGraphInput {
  target?: string;
  engagementName?: string;
  assets: Asset[];
  services: Service[];
  findings: Finding[];
  chains: AttackChain[];
  content?: ContentMap;
  hostRaw?: unknown;
  history?: HttpHistory;
}
export interface EngagementGraphOptions {
  allRoutes?: boolean;    // include endpoints with no finding (full surface), not just ones that matter
  showServices?: boolean; // include open ports/services as nodes
  showAgents?: boolean;   // include the producing executor skills as nodes
  sevMin?: number;        // minimum severity rank for a finding to appear (0 = all)
  focusHost?: string | null;
}

const uniq = <T,>(a: T[]): T[] => Array.from(new Set(a));
const norm = (h: string): string => hostOf(h).toLowerCase();
const sevRankOf = (f: Finding): number => SEVERITY[f.severity]?.rank ?? 0;

/** The executor skill behind a finding (its reviewer is "<skill>-verify"). */
export function producerOf(f: Finding): string | undefined {
  const r = f.review?.reviewer;
  if (!r) return undefined;
  const slug = r.replace(/-verify$/, "").replace(/^redstrike-/, "").trim();
  return slug || undefined;
}

/** Short endpoint label for a route node (last path segment, or the full short path). */
function routeLabel(rt: SiteRoute): string {
  const p = rt.path.split(/[?#]/)[0] || "/";
  if (p === "/") return "/";
  const segs = p.split("/").filter(Boolean);
  const tail = segs[segs.length - 1] || "/";
  return tail.length > 22 ? "…" + tail.slice(-21) : tail;
}

export function buildEngagementGraph(
  input: EngagementGraphInput,
  opts: EngagementGraphOptions = {},
): EngagementGraph {
  const { allRoutes = false, showServices = false, showAgents = false, sevMin = 0, focusHost = null } = opts;
  const focus = focusHost ? norm(focusHost) : null;

  const nonComposite = input.findings.filter((f) => !f.composite);
  const site = buildSiteMap(input.content, input.hostRaw, nonComposite, input.history);

  // finding → the hostnames + routes it touches
  const findingHosts = (f: Finding) => uniq(assetHosts(f.asset).map((h) => h.toLowerCase()));
  const routesByFinding = new Map<string, SiteRoute[]>();
  for (const rt of site.routes) {
    for (const fid of rt.findingIds) {
      const list = routesByFinding.get(fid);
      if (list) list.push(rt); else routesByFinding.set(fid, [rt]);
    }
  }

  // visible findings: severity floor + focus-host membership
  const visFindings = nonComposite.filter((f) => {
    if (sevRankOf(f) < sevMin) return false;
    if (!focus) return true;
    const onHost = findingHosts(f).includes(focus);
    const onRoute = (routesByFinding.get(f.id) ?? []).some((rt) => norm(rt.host) === focus);
    return onHost || onRoute;
  });
  const visFindingIds = new Set(visFindings.map((f) => f.id));

  // ---- host universe (asset inventory ∪ services ∪ routes ∪ finding assets) ----
  const hostMeta = new Map<string, Asset>();
  for (const a of input.assets) {
    if (a.kind === "domain" || a.kind === "subdomain" || a.kind === "ip" || a.kind === "cidr") {
      const h = norm(a.value);
      if (h && h !== "—" && !hostMeta.has(h)) hostMeta.set(h, a);
    }
  }
  const hostNames = new Set<string>(hostMeta.keys());
  for (const s of input.services) { const h = norm(s.host); if (h && h !== "—") hostNames.add(h); }
  for (const rt of site.routes) { const h = norm(rt.host); if (h && h !== "—") hostNames.add(h); }
  for (const f of visFindings) for (const h of findingHosts(f)) if (h && h !== "—") hostNames.add(h);

  const hosts = Array.from(hostNames).filter((h) => !focus || h === focus);

  // visible routes: on a visible host, and (all surface ∥ has a visible finding)
  const hostSet = new Set(hosts);
  const visRoutes = site.routes.filter((rt) => {
    const h = norm(rt.host);
    if (!hostSet.has(h)) return false;
    if (allRoutes) return true;
    return rt.findingIds.some((id) => visFindingIds.has(id));
  });
  const visRouteIds = new Set(visRoutes.map((rt) => rt.id));

  // ---- assemble nodes ----
  const nodes: GNode[] = [];
  const nodeById = new Map<string, GNode>();
  const add = (n: GNode) => { nodes.push(n); nodeById.set(n.id, n); return n; };

  const scopeId = "scope";
  if (hosts.length) {
    add({ id: scopeId, kind: "scope", label: input.engagementName || input.target || "Engagement",
      sub: input.target, col: 0, row: 0, sevRank: 0 });
  }

  for (const h of hosts) {
    const a = hostMeta.get(h);
    add({ id: "host:" + h, kind: "host", label: h, host: h, hostName: h, col: 1, row: 0, sevRank: 0,
      sub: a?.coverage, meta: { coverage: a?.coverage, status: a?.status, server: a?.server, tier: a?.tier } });
  }

  if (showServices) {
    const seen = new Set<string>();
    for (const s of input.services) {
      const h = norm(s.host);
      if (!hostSet.has(h)) continue;
      const id = `svc:${h}:${s.port}/${s.proto ?? "tcp"}`;
      if (seen.has(id)) continue; seen.add(id);
      add({ id, kind: "service", label: `${s.port}/${s.proto ?? "tcp"}`, sub: s.product || s.service,
        host: h, col: 2, row: 0, sevRank: 0, meta: { service: s.service, version: s.version, tls: s.tls, flagged: s.flagged } });
    }
  }

  for (const rt of visRoutes) {
    const h = norm(rt.host);
    add({ id: "route:" + rt.id, kind: "route", label: routeLabel(rt), sub: rt.path.split(/[?#]/)[0],
      host: h, col: 2, row: 0, sevRank: 0, meta: { method: rt.method, status: rt.status, type: rt.type, params: rt.params.length } });
  }

  for (const f of visFindings) {
    add({ id: "find:" + f.id, kind: "finding", label: f.id, sub: f.title, col: 3, row: 0,
      sevRank: sevRankOf(f), severity: f.severity, findingId: f.id,
      host: findingHosts(f)[0], meta: { title: f.title, verdict: f.review?.verdict, producer: producerOf(f) } });
  }

  // ---- edges ----
  const edges: GEdge[] = [];
  const edgeSeen = new Set<string>();
  const link = (source: string, target: string, rel: GEdgeRel) => {
    if (!nodeById.has(source) || !nodeById.has(target)) return;
    const id = `${source}->${target}`;
    if (edgeSeen.has(id)) return; edgeSeen.add(id);
    edges.push({ id, source, target, rel });
  };

  for (const h of hosts) link(scopeId, "host:" + h, "scope");
  for (const n of nodes) if (n.kind === "service") link("host:" + n.host, n.id, "surface");
  for (const rt of visRoutes) link("host:" + norm(rt.host), "route:" + rt.id, "surface");

  // finding → its parent surface: prefer the matched endpoint, else the host root.
  // Tracks the primary parent id for the layout spine.
  const spineParent = new Map<string, string>();
  for (const f of visFindings) {
    const fid = "find:" + f.id;
    const anchorRoutes = (routesByFinding.get(f.id) ?? []).filter((rt) => visRouteIds.has(rt.id) && (!focus || norm(rt.host) === focus));
    if (anchorRoutes.length) {
      for (const rt of anchorRoutes) link("route:" + rt.id, fid, "finding");
      spineParent.set(fid, "route:" + anchorRoutes[0].id);
    } else {
      const fHosts = findingHosts(f).filter((h) => hostSet.has(h) && (!focus || h === focus));
      for (const h of fHosts) link("host:" + h, fid, "finding");
      if (fHosts.length) spineParent.set(fid, "host:" + fHosts[0]);
    }
  }

  // chains that compose a visible finding
  for (const c of input.chains) {
    const steps = (c.steps ?? []).filter((s) => s.finding_id && visFindingIds.has(s.finding_id));
    if (!steps.length) continue;
    const cid = "chain:" + c.id;
    add({ id: cid, kind: "chain", label: c.title || c.id, sub: c.feasibility, col: 4, row: 0, sevRank: 0,
      meta: { feasibility: c.feasibility, impact: c.impact, steps: c.steps?.length } });
    for (const s of steps) link("find:" + s.finding_id, cid, "chain");
  }

  // producing executor skills
  if (showAgents) {
    for (const f of visFindings) {
      const slug = producerOf(f);
      if (!slug) continue;
      const aid = "agent:" + slug;
      if (!nodeById.has(aid)) add({ id: aid, kind: "agent", label: slug, sub: "executor", col: 4, row: 0, sevRank: 0, agentSlug: slug });
      link("find:" + f.id, aid, "agent");
    }
  }

  // ---- worst-severity roll-up onto surface + host nodes ----
  const bump = (id: string | undefined, rank: number) => { if (!id) return; const n = nodeById.get(id); if (n && rank > n.sevRank) n.sevRank = rank; };
  for (const f of visFindings) {
    const rank = sevRankOf(f);
    for (const rt of routesByFinding.get(f.id) ?? []) if (visRouteIds.has(rt.id)) bump("route:" + rt.id, rank);
    for (const h of findingHosts(f)) if (hostSet.has(h)) bump("host:" + h, rank);
  }

  // ---- layout rows: tidy layered DFS over the spine, barycenter the col-4 sinks ----
  const childrenOf = new Map<string, string[]>();
  const pushChild = (p: string, c: string) => { const l = childrenOf.get(p); if (l) l.push(c); else childrenOf.set(p, [c]); };
  for (const n of nodes) {
    if (n.kind === "host") pushChild(scopeId, n.id);
    else if (n.kind === "service" || n.kind === "route") pushChild("host:" + n.host, n.id);
    else if (n.kind === "finding") { const p = spineParent.get(n.id); if (p) pushChild(p, n.id); }
  }
  // deterministic sibling order: severity desc, then kind, then label
  const kindOrder: Record<GNodeKind, number> = { scope: 0, host: 1, service: 2, route: 3, finding: 4, chain: 5, agent: 6 };
  const orderChildren = (ids: string[]) =>
    ids.slice().sort((a, b) => {
      const na = nodeById.get(a)!, nb = nodeById.get(b)!;
      return nb.sevRank - na.sevRank || kindOrder[na.kind] - kindOrder[nb.kind] || na.label.localeCompare(nb.label);
    });

  let slot = 0;
  const rowOf = new Map<string, number>();
  const visit = (id: string): number => {
    const kids = childrenOf.get(id);
    if (!kids || !kids.length) { const r = slot++; rowOf.set(id, r); return r; }
    const rs = orderChildren(kids).map(visit);
    const r = rs.reduce((s, x) => s + x, 0) / rs.length;
    rowOf.set(id, r);
    return r;
  };
  if (nodeById.has(scopeId)) visit(scopeId);
  // any spine node not reached (defensive) gets appended
  for (const n of nodes) if ((n.kind === "host" || n.kind === "service" || n.kind === "route" || n.kind === "finding") && !rowOf.has(n.id)) rowOf.set(n.id, slot++);

  // col-4 sinks (chain / agent): mean row of the findings they connect, else append
  const incoming = new Map<string, string[]>();
  for (const e of edges) { const l = incoming.get(e.target); if (l) l.push(e.source); else incoming.set(e.target, [e.source]); }
  const sinks: GNode[] = [];
  for (const n of nodes) {
    if (n.kind !== "chain" && n.kind !== "agent") continue;
    const srcs = (incoming.get(n.id) ?? []).map((s) => rowOf.get(s)).filter((v): v is number => v != null);
    rowOf.set(n.id, srcs.length ? srcs.reduce((s, x) => s + x, 0) / srcs.length : slot++);
    sinks.push(n);
  }
  // Barycenter alone can stack many-to-one sinks on the SAME row — e.g. a finding's chain AND
  // its producing agent both inherit that finding's row, drawing two boxes on top of each other.
  // Spread them: keep the barycenter order, then enforce a minimum vertical gap so col-4 nodes
  // never collide. Deterministic (sorted) and viewport-independent.
  const SINK_GAP = 1;
  sinks.sort((a, b) =>
    (rowOf.get(a.id)! - rowOf.get(b.id)!) || kindOrder[a.kind] - kindOrder[b.kind] || a.label.localeCompare(b.label));
  let sinkPrev = -Infinity;
  for (const n of sinks) {
    const r = Math.max(rowOf.get(n.id)!, sinkPrev + SINK_GAP);
    rowOf.set(n.id, r);
    sinkPrev = r;
  }

  for (const n of nodes) n.row = rowOf.get(n.id) ?? 0;

  // true vertical extent (spread sinks can reach past `slot`); feeds the view's fit signature.
  const maxRow = nodes.reduce((m, n) => Math.max(m, n.row), 0);
  const stats = { scope: 0, host: 0, service: 0, route: 0, finding: 0, chain: 0, agent: 0, worstSev: 0,
    rows: nodes.length ? Math.max(Math.ceil(slot), Math.ceil(maxRow) + 1) : 0 } as EngagementGraph["stats"];
  for (const n of nodes) { stats[n.kind]++; if (n.sevRank > stats.worstSev) stats.worstSev = n.sevRank; }

  return { nodes, edges, stats };
}
