// Source-audit surface builders — the white-box analogs of lib/siteMap.ts.
//
// A WHITE-BOX source-code audit has none of the black-box web artifacts (host_discovery /
// content.json / js-analysis) the Site Map + Assets views were built for. Instead the feeders
// emit:
//   • surface_ledger.json        — the app's endpoints / forms / sinks, each routed to a hunter
//   • source-audit/source_context.json — the structural route map + code-asset inventory
// These builders turn those into:
//   • a MODULE/FILE tree of the app's routes (the analog of the host→path URL tree)
//   • grouped attack-surface lists (endpoints / forms / sinks)
//   • a code-asset inventory (modules, dependencies, languages, sink leads, secrets)
// Pure + deterministic so the views stay thin. Nothing here fetches or walks the 30k-file
// source/ checkout — it reads only the structured artifacts the server serves.

import type {
  Engagement, Finding, Severity, SourceContext, SourceStructural, SourceCandidate,
  SurfaceLedger, SurfaceItem,
} from "./types";
import { SEVERITY } from "./theme";
import { isReportable } from "./format";

/** Is this a white-box SOURCE-CODE audit (vs a black-box web engagement)? Keyed off the
 *  scope.source grant the CLI records; the served source_context is a fallback signal. Web
 *  engagements (no scope.source, no source_context) stay false, so they keep the existing views. */
export function isSourceEngagement(eng?: Engagement | null, sourceContext?: SourceContext): boolean {
  if (eng?.source?.repo_url) return true;
  if (sourceContext && (Array.isArray(sourceContext.structural) || Array.isArray(sourceContext.candidates))) return true;
  return false;
}

/** A short repo label from a git URL ("github.com/shopware/shopware.git" → "shopware/shopware"). */
export function repoLabel(url?: string): string {
  if (!url) return "";
  const m = url.replace(/\.git$/, "").match(/[:/]([^/]+\/[^/]+)$/);
  return m ? m[1] : url.replace(/^https?:\/\//, "");
}

/* ── file-path extraction ───────────────────────────────────────────────────
 * Finding assets on a source audit embed one or more source paths, e.g.
 *   "shopware repo (trunk 7de25bac): src/Core/Checkout/Cart/RedisCartPersister.php:60 + src/…"
 * We pull every path-shaped, code-extension token so findings link to file nodes. */
const CODE_EXT = "php|twig|js|mjs|cjs|ts|tsx|jsx|vue|scss|css|less|xml|ya?ml|json|html|sql|go|py|rb|java|cs|c|cpp|h|hpp|rs|kt|swift";
// Anchored at a recognized source root so a finding's relative path FRAGMENT (e.g. "Controller/X.php")
// doesn't spawn a junk top-level module node — the tree stays tied to the real repo layout. Greedy so
// a compound extension like ".html.twig" is captured whole; the char class excludes space/colon so it
// stops cleanly at a ":line" suffix or the next token.
const FILE_RE = new RegExp(`((?:src|public|vendor|tests?|platform|config|bin|custom)/[\\w.@/-]+\\.(?:${CODE_EXT}))`, "g");

/** Every source file path referenced in a finding's `asset` (deduped, line suffixes stripped). */
export function filesInAsset(asset: string): string[] {
  const out = new Set<string>();
  const re = new RegExp(FILE_RE);
  let m: RegExpExecArray | null;
  while ((m = re.exec(asset || "")) !== null) out.add(m[1]);
  return Array.from(out);
}

const sevRank = (s?: Severity | null): number => (s ? SEVERITY[s]?.rank ?? 0 : 0);

/* ── module / file tree ─────────────────────────────────────────────────── */

export interface SourceNode {
  key: string;             // full path prefix, e.g. "src/Core/Checkout" or the file path
  label: string;           // last path segment
  path: string;            // same as key
  isFile: boolean;
  children: SourceNode[];
  routes: SourceStructural[]; // structural route rows that live in this file
  findingIds: string[];    // reportable findings referencing this file
  parent: SourceNode | null;
}

export interface SourceTree {
  roots: SourceNode[];
  nodes: Map<string, SourceNode>;
  fileCount: number;
  routeCount: number;      // structural rows attached to files
  unauthCount: number;     // kind === "unauth-route"
  withFindings: number;    // files carrying >=1 reportable finding
}

/** "unauth" / "auth-guard" / "state-change" styling key for a structural kind. */
export function routeKindTone(kind?: string): { label: string; color: string } {
  switch ((kind || "").toLowerCase()) {
    case "unauth-route": return { label: "unauth", color: "#f43f5e" };
    case "auth-guard": return { label: "auth-guard", color: "#22c55e" };
    case "state-change-route": return { label: "state-change", color: "#f59e0b" };
    case "mass-assignment": return { label: "mass-assign", color: "#a855f7" };
    case "id-from-param": return { label: "id-from-param", color: "#38bdf8" };
    case "writable-path": return { label: "writable", color: "#f59e0b" };
    case "web-exec-path": return { label: "web-exec", color: "#f43f5e" };
    default: return { label: kind ? kind.replace(/-/g, " ") : "route", color: "#64748b" };
  }
}

function ensurePath(tree: SourceTree, file: string): SourceNode | null {
  const segs = (file || "").split("/").filter(Boolean);
  if (!segs.length) return null;
  let parent: SourceNode | null = null;
  let acc = "";
  for (let i = 0; i < segs.length; i++) {
    acc = acc ? `${acc}/${segs[i]}` : segs[i];
    let node = tree.nodes.get(acc);
    if (!node) {
      node = {
        key: acc, label: segs[i], path: acc,
        isFile: i === segs.length - 1 && /\.[a-z0-9]+$/i.test(segs[i]),
        children: [], routes: [], findingIds: [], parent,
      };
      tree.nodes.set(acc, node);
      if (parent) parent.children.push(node); else tree.roots.push(node);
    }
    parent = node;
  }
  return parent;
}

/** Build the module/file tree from the structural route map + reportable findings. */
export function buildSourceTree(sc: SourceContext | undefined, findings: Finding[]): SourceTree {
  const tree: SourceTree = { roots: [], nodes: new Map(), fileCount: 0, routeCount: 0, unauthCount: 0, withFindings: 0 };
  const structural = Array.isArray(sc?.structural) ? sc!.structural! : [];
  for (const row of structural) {
    if (!row || typeof row.file !== "string" || !row.file) continue;
    const node = ensurePath(tree, row.file.replace(/\/$/, "") || row.file);
    if (!node) continue;
    node.routes.push(row);
    tree.routeCount++;
    if ((row.kind || "").toLowerCase() === "unauth-route") tree.unauthCount++;
  }
  // link reportable findings to the file nodes they name
  for (const f of findings) {
    if (!isReportable(f)) continue;
    for (const file of filesInAsset(f.asset)) {
      const node = ensurePath(tree, file);
      if (node && !node.findingIds.includes(f.id)) node.findingIds.push(f.id);
    }
  }
  // sort children: dirs before files, then alpha
  const sortRec = (n: SourceNode) => {
    n.children.sort((a, b) => Number(a.isFile) - Number(b.isFile) || a.label.localeCompare(b.label));
    n.children.forEach(sortRec);
  };
  tree.roots.sort((a, b) => a.label.localeCompare(b.label));
  tree.roots.forEach(sortRec);
  for (const n of tree.nodes.values()) {
    if (n.isFile || n.routes.length) tree.fileCount++;
    if (n.findingIds.length) tree.withFindings++;
  }
  return tree;
}

/** Every route at or beneath a node (depth-first). */
export function subtreeRoutes(n: SourceNode, out: SourceStructural[] = []): SourceStructural[] {
  out.push(...n.routes);
  for (const c of n.children) subtreeRoutes(c, out);
  return out;
}

/** Every finding id at or beneath a node. */
export function subtreeFindingIds(n: SourceNode, out: Set<string> = new Set()): Set<string> {
  for (const id of n.findingIds) out.add(id);
  for (const c of n.children) subtreeFindingIds(c, out);
  return out;
}

/** Worst reportable-finding rank in a node's subtree (0 = none). */
export function nodeWorstRank(n: SourceNode, byId: Map<string, Finding>): number {
  let rank = 0;
  for (const id of subtreeFindingIds(n)) { const f = byId.get(id); if (f) rank = Math.max(rank, sevRank(f.severity)); }
  return rank;
}

/* ── attack surface (surface_ledger) ────────────────────────────────────── */

export interface GroupedSurfaces {
  endpoints: SurfaceItem[];
  forms: SurfaceItem[];
  sinks: SurfaceItem[];
  other: SurfaceItem[];
  total: number;
}

export function groupSurfaces(sl?: SurfaceLedger): GroupedSurfaces {
  const g: GroupedSurfaces = { endpoints: [], forms: [], sinks: [], other: [], total: 0 };
  for (const s of Array.isArray(sl?.surfaces) ? sl!.surfaces! : []) {
    if (!s || typeof s.value !== "string") continue;
    g.total++;
    const k = (s.kind || "").toLowerCase();
    if (k === "endpoint") g.endpoints.push(s);
    else if (k === "form") g.forms.push(s);
    else if (k === "sink") g.sinks.push(s);
    else g.other.push(s);
  }
  return g;
}

/** Parse a sink surface value "expr @ src/Foo.php:138 [sqli-blind]" into its parts. */
export function parseSink(value: string): { expr: string; file?: string; line?: number; route?: string } {
  const route = value.match(/\[([^\]]+)\]\s*$/)?.[1];
  const loc = value.match(/@\s*([\w.@/-]+\.[a-z0-9]+):(\d+)/i);
  let expr = value;
  if (loc) expr = value.slice(0, value.indexOf("@")).trim();
  else if (route) expr = value.replace(/\[[^\]]+\]\s*$/, "").trim();
  return { expr, file: loc?.[1], line: loc ? Number(loc[2]) : undefined, route };
}

/* ── code-asset inventory (modules) ─────────────────────────────────────── */

export interface SourceModule {
  key: string;             // "src/Core/Checkout"
  routes: number;          // structural rows under this module
  leads: number;           // sink/vuln candidates under this module
  findings: number;        // reportable findings referencing files under this module
  worst: Severity | null;  // worst reportable-finding severity in the module
}

/** Module key = first up-to-3 path segments (the app's coarse module granularity). */
export function moduleKey(file?: string): string {
  const parts = (file || "").split("/").filter(Boolean);
  if (!parts.length) return "(root)";
  // a trailing filename segment doesn't count toward the 3-segment module prefix
  const dirs = /\.[a-z0-9]+$/i.test(parts[parts.length - 1]) ? parts.slice(0, -1) : parts;
  return (dirs.length ? dirs : parts).slice(0, 3).join("/") || "(root)";
}

/** Group the structural routes + sink leads + findings into code modules, risk-ranked. */
export function buildModules(sc: SourceContext | undefined, findings: Finding[]): SourceModule[] {
  const map = new Map<string, SourceModule>();
  const get = (k: string): SourceModule => {
    let m = map.get(k);
    if (!m) { m = { key: k, routes: 0, leads: 0, findings: 0, worst: null }; map.set(k, m); }
    return m;
  };
  for (const r of Array.isArray(sc?.structural) ? sc!.structural! : []) {
    if (r?.file) get(moduleKey(r.file)).routes++;
  }
  for (const c of Array.isArray(sc?.candidates) ? sc!.candidates! : []) {
    if (c?.file) get(moduleKey(c.file)).leads++;
  }
  for (const f of findings) {
    if (!isReportable(f)) continue;
    const mods = new Set(filesInAsset(f.asset).map(moduleKey));
    for (const k of mods) {
      const m = get(k);
      m.findings++;
      if (!m.worst || sevRank(f.severity) > sevRank(m.worst)) m.worst = f.severity;
    }
  }
  return Array.from(map.values()).sort(
    (a, b) => sevRank(b.worst) - sevRank(a.worst) || b.findings - a.findings || b.routes + b.leads - (a.routes + a.leads) || a.key.localeCompare(b.key),
  );
}

/** A tolerant severity→meta lookup for free-form confidence/severity-ish strings. */
export function confidenceColor(c?: string): string {
  switch ((c || "").toLowerCase()) {
    case "high": return "#f43f5e";
    case "medium": return "#f59e0b";
    case "low": return "#64748b";
    default: return "#94a3b8";
  }
}
