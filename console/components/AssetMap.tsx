"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Globe, Network, Plus, Minus, Maximize2, Search, ShieldAlert, X, Folder, Shrink, Expand,
} from "lucide-react";
import type { Asset, AssetKind, Service, Finding } from "@/lib/types";
import { COVERAGE, SEVERITY, ink } from "@/lib/theme";
import { cx, assetHosts } from "@/lib/format";
import { buildAssetTree, walkTree, type TreeNode, type RiskLevel, type RiskInfo } from "@/lib/assetTree";

/* ───────────────────────────────────────────────────────────────────────────
   Asset mindmap — a collapsible radial tree of the domain hierarchy.

   The registrable domain sits at the centre; sub-domains branch out as a radial
   dendrogram. The long tail of plain untested hosts is folded into expandable
   letter buckets, while risky / has-findings hosts stay as named spokes. Every
   branch aggregates the worst risk + findings + host count of its subtree, so a
   collapsed node still shows a risk ring and a count. Pan (drag), wheel/buttons
   to zoom, click a branch to expand/collapse, click a host to open its detail.
   ──────────────────────────────────────────────────────────────────────────── */

const STAGE_W = 1040, STAGE_H = 600, PAD = 74;
const RING = 150;          // base radial gap between depth rings (pre-fit)
const MIN_ARC = 24;        // min arc spacing between adjacent leaves (pre-fit) → no overlap
const HOST_KINDS = new Set<AssetKind>(["domain", "subdomain", "ip", "cidr"]);
const RISK_COLOR = { high: "#ef4444", elevated: "#f59e0b" } as const;
const clamp = (n: number, a: number, b: number) => Math.max(a, Math.min(b, n));

export function AssetMap({
  assets, orgName, services = [], findings = [], onSelectHost, selectedHost,
}: { assets: Asset[]; orgName: string; services?: Service[]; findings?: Finding[]; onSelectHost?: (host: string) => void; selectedHost?: string }) {
  // per-host risk: worst finding severity + service posture (exposed/outdated) + open ports
  const hostRisk = useMemo(() => {
    const agg = new Map<string, { open: number; exposed: boolean; outdated: boolean }>();
    for (const s of services) {
      if (s.flagged === "out-of-scope") continue;
      const a = agg.get(s.host) ?? { open: 0, exposed: false, outdated: false };
      if (s.state === "open") a.open += 1;
      if (s.flagged === "exposed") a.exposed = true;
      if (s.flagged === "outdated") a.outdated = true;
      agg.set(s.host, a);
    }
    const sev = new Map<string, number>();
    for (const f of findings) {
      if (f.composite) continue;
      const rank = SEVERITY[f.severity]?.rank ?? 0;
      for (const h of assetHosts(f.asset)) sev.set(h, Math.max(sev.get(h) ?? 0, rank));
    }
    const m = new Map<string, RiskInfo>();
    new Set<string>([...agg.keys(), ...sev.keys()]).forEach((h) => {
      const a = agg.get(h) ?? { open: 0, exposed: false, outdated: false };
      const r = sev.get(h) ?? 0;
      const level: RiskLevel = a.exposed || r >= 4 ? "high" : a.outdated || r >= 1 ? "elevated" : "none";
      m.set(h, { level, open: a.open });
    });
    return m;
  }, [services, findings]);

  const tree = useMemo(() => buildAssetTree(assets, orgName, hostRisk), [assets, orgName, hostRisk]);

  // every branch below the root collapses by default, so the first view is one clean
  // ring of top-level branches (domains + letter buckets + risky host spokes) to drill into
  const defaultCollapsed = useMemo(() => {
    const s = new Set<string>();
    walkTree(tree, (n) => { if (n !== tree && n.children.length > 0) s.add(n.id); });
    return s;
  }, [tree]);
  const [collapsed, setCollapsed] = useState<Set<string>>(defaultCollapsed);
  useEffect(() => { setCollapsed(new Set(defaultCollapsed)); }, [defaultCollapsed]);

  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "risk" | "untested">("all");
  const q = query.trim().toLowerCase();

  // nodes whose subtree contains a search match → auto-expand their branch
  const hasMatch = useMemo(() => {
    const s = new Set<string>();
    if (!q) return s;
    const visit = (n: TreeNode): boolean => {
      let m = n.kind === "host" && n.full.toLowerCase().includes(q);
      for (const c of n.children) if (visit(c)) m = true;
      if (m) s.add(n.id);
      return m;
    };
    visit(tree);
    return s;
  }, [tree, q]);

  const layout = useMemo(() => radialLayout(tree, collapsed, hasMatch), [tree, collapsed, hasMatch]);

  const totals = useMemo(() => {
    const t = { hosts: 0, tested: 0, out: 0, high: 0, elevated: 0 };
    for (const a of assets) {
      if (!HOST_KINDS.has(a.kind)) continue;
      t.hosts++;
      if (a.scope === "out") { t.out++; continue; }
      if (a.coverage === "tested") t.tested++;
      const lv = hostRisk.get(a.value)?.level;
      if (lv === "high") t.high++; else if (lv === "elevated") t.elevated++;
    }
    return t;
  }, [assets, hostRisk]);

  const [view, setView] = useState({ tx: 0, ty: 0, s: 1 });
  const [dragging, setDragging] = useState(false);
  const [hover, setHover] = useState<{ id: string; left: number; top: number } | null>(null);
  const dragRef = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const toggle = (id: string) => setCollapsed((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allExpanded = collapsed.size === 0;
  const expandAll = () => setCollapsed(new Set());
  const collapseAll = () => setCollapsed(new Set(defaultCollapsed));

  const onNodeClick = (n: TreeNode) => {
    if (n.children.length > 0) toggle(n.id);
    else if (n.kind === "host") onSelectHost?.(n.full);
  };

  // anchor the tooltip to the hovered element's real screen rect (the SVG scales via
  // viewBox, so node stage-coords don't map 1:1 to container pixels)
  const enter = (e: React.MouseEvent, n: TreeNode) => {
    const c = containerRef.current?.getBoundingClientRect();
    const b = (e.currentTarget as SVGGElement).getBoundingClientRect();
    if (!c) return;
    setHover({ id: n.id, left: b.left + b.width / 2 - c.left, top: b.top - c.top });
  };

  // wheel zoom (non-passive so we can preventDefault the page scroll)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      setView((v) => ({ ...v, s: clamp(v.s * (e.deltaY < 0 ? 1.12 : 0.89), 0.4, 8) }));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const onDown = (e: React.MouseEvent) => { dragRef.current = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty }; setDragging(true); };
  const onMove = (e: React.MouseEvent) => {
    const d = dragRef.current; if (!d) return;
    setView((v) => ({ ...v, tx: d.tx + (e.clientX - d.x), ty: d.ty + (e.clientY - d.y) }));
  };
  const onUp = () => { dragRef.current = null; setDragging(false); };
  const zoom = (f: number) => setView((v) => ({ ...v, s: clamp(v.s * f, 0.4, 8) }));
  const reset = () => { setView({ tx: 0, ty: 0, s: 1 }); collapseAll(); };

  const nodeOpacity = (n: TreeNode): number => {
    if (q) return hasMatch.has(n.id) ? 1 : 0.12;
    if (filter === "risk") return n.risk !== "none" ? 1 : n.kind === "host" ? 0.16 : 0.5;
    if (filter === "untested") {
      if (n.kind === "host") return n.coverage === "tested" ? 0.18 : 1;
      return 0.9;
    }
    return 1;
  };

  // static tree layer — memoised so hover/pan never re-renders the whole tree
  const treeLayer = useMemo(() => (
    <g>
      {/* links first (under the nodes) */}
      {layout.links.map(([s, t], i) => (
        <path key={`l${i}`} d={linkPath(s, t)} fill="none" stroke={ink(0.16)} strokeWidth={Math.max(0.6, 1.1 * layout.fit)}
              opacity={q && !hasMatch.has(t.id) ? 0.15 : 0.85} />
      ))}
      {/* nodes */}
      {layout.nodes.map((n) => {
        const vis = nodeFill(n);
        const op = nodeOpacity(n);
        const expandable = n.children.length > 0;
        const showLabel = labelByDefault(n);
        return (
          <g key={n.id} opacity={op} style={{ transition: "opacity .18s ease" }}
             className={expandable || n.kind === "host" ? "cursor-pointer" : undefined}
             onMouseDown={(e) => e.stopPropagation()}
             onMouseEnter={(e) => enter(e, n)} onMouseLeave={() => setHover(null)}
             onClick={(e) => { e.stopPropagation(); onNodeClick(n); }}>
            {n.risk !== "none" && (
              <circle cx={n.x} cy={n.y} r={n.r! + 3} fill={RISK_COLOR[n.risk]} opacity={0.14} />
            )}
            <circle cx={n.x} cy={n.y} r={n.r} fill={vis.fill} stroke={vis.stroke} strokeWidth={vis.sw} strokeDasharray={vis.dash} />
            {n.risk !== "none" && (
              <circle cx={n.x} cy={n.y} r={n.r! + 1.8} fill="none" stroke={RISK_COLOR[n.risk]} strokeWidth={1.6} />
            )}
            {/* a dashed outer ring marks a collapsed, expandable branch */}
            {expandable && collapsed.has(n.id) && n.kind !== "root" && (
              <circle cx={n.x} cy={n.y} r={n.r! + 3.4} fill="none" stroke={ink(0.4)} strokeWidth={1} strokeDasharray="1.5 2.5" />
            )}
            {showLabel && <NodeLabel n={n} />}
          </g>
        );
      })}
    </g>
  ), [layout, q, filter, collapsed, hasMatch]); // eslint-disable-line react-hooks/exhaustive-deps

  const hovered = hover ? layout.nodes.find((n) => n.id === hover.id) : undefined;
  const selectedNode = selectedHost ? layout.nodes.find((n) => n.kind === "host" && n.full === selectedHost) : undefined;

  return (
    <div
      ref={containerRef}
      className="graph-grid relative h-[600px] select-none overflow-hidden rounded-xl border border-line bg-card2"
      style={{ cursor: dragging ? "grabbing" : "grab" }}
      onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={() => { onUp(); setHover(null); }}
    >
      <svg width="100%" height="100%" viewBox={`0 0 ${STAGE_W} ${STAGE_H}`} preserveAspectRatio="xMidYMid meet" className="block">
        <g transform={`translate(${STAGE_W / 2 + view.tx} ${STAGE_H / 2 + view.ty}) scale(${view.s})`}>
          {treeLayer}

          {/* hovered emphasis + always-on label */}
          {hovered && (
            <g pointerEvents="none">
              <circle cx={hovered.x} cy={hovered.y} r={hovered.r! + 3} fill="none" stroke={ink(0.5)} strokeWidth={1.4} />
              {!labelByDefault(hovered) && <NodeLabel n={hovered} />}
            </g>
          )}
          {/* selected host ring + label */}
          {selectedNode && (
            <g pointerEvents="none">
              <circle cx={selectedNode.x} cy={selectedNode.y} r={selectedNode.r! + 4} fill="none" stroke={ink(0.9)} strokeWidth={2} />
              {!labelByDefault(selectedNode) && <NodeLabel n={selectedNode} />}
            </g>
          )}
        </g>
      </svg>

      {/* tooltip */}
      {hover && hovered && (
        <HoverCard n={hovered} open={hostRisk.get(hovered.full)?.open ?? 0} collapsedState={collapsed.has(hovered.id)}
                   left={hover.left} top={hover.top} containerW={containerRef.current?.clientWidth ?? STAGE_W} />
      )}

      {/* top bar — search + filters (left) · stats (right) */}
      <div className="pointer-events-none absolute inset-x-3 top-3 flex items-start justify-between gap-3">
        <div className="pointer-events-auto flex flex-wrap items-center gap-1.5">
          <div className="flex items-center gap-1.5 rounded-lg border border-line bg-card/85 px-2 py-1 backdrop-blur">
            <Search size={13} className="text-muted" />
            <input
              value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find host…"
              onMouseDown={(e) => e.stopPropagation()}
              className="w-32 bg-transparent text-xs text-fg placeholder:text-muted focus:outline-none"
            />
            {query && <button onMouseDown={(e) => e.stopPropagation()} onClick={() => setQuery("")} className="text-muted hover:text-fg"><X size={12} /></button>}
          </div>
          <div className="flex items-center overflow-hidden rounded-lg border border-line bg-card/85 backdrop-blur">
            {([["all", `All ${totals.hosts}`], ["risk", `Risk ${totals.high + totals.elevated}`], ["untested", `Untested ${totals.hosts - totals.tested - totals.out}`]] as const).map(([k, label], i) => (
              <button key={k} onMouseDown={(e) => e.stopPropagation()} onClick={() => setFilter(k)}
                className={cx("px-2.5 py-1 text-xs transition", i > 0 && "border-l border-line",
                  filter === k ? "bg-fg/10 font-medium text-fg" : "text-muted hover:text-fg")}>
                {label}
              </button>
            ))}
          </div>
          <button onMouseDown={(e) => e.stopPropagation()} onClick={allExpanded ? collapseAll : expandAll}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-card/85 px-2.5 py-1 text-xs text-muted backdrop-blur transition hover:text-fg">
            {allExpanded ? <Shrink size={13} /> : <Expand size={13} />}
            {allExpanded ? "Collapse" : "Expand all"}
          </button>
        </div>
        <div className="pointer-events-none flex items-center gap-1.5">
          <Stat value={`${Math.round((totals.tested / Math.max(1, totals.hosts - totals.out)) * 100)}%`} label="tested" />
          {totals.high + totals.elevated > 0 && (
            <Stat value={String(totals.high + totals.elevated)} label="at risk" tone={totals.high ? "#ef4444" : "#f59e0b"} />
          )}
        </div>
      </div>

      {/* legend */}
      <div className="absolute bottom-3 left-14 w-auto rounded-xl border border-line bg-card/85 px-3 py-2 text-xs backdrop-blur">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted">
          <Swatch label="Tested" style={{ background: COVERAGE.tested.color }} />
          <Swatch label="In progress" style={{ background: COVERAGE["in-progress"].color }} />
          <Swatch label="Untested" style={{ background: "rgb(var(--card))", border: `1.5px solid ${COVERAGE.untested.color}` }} />
          <Swatch label="Group" style={{ background: "rgb(var(--card))", border: "1.5px dashed rgb(var(--fg) / 0.4)" }} />
          <span className="h-3 w-px bg-line" />
          <Swatch label="High" style={{ background: "transparent", border: `2px solid ${RISK_COLOR.high}` }} />
          <Swatch label="Elevated" style={{ background: "transparent", border: `2px solid ${RISK_COLOR.elevated}` }} />
        </div>
      </div>

      {/* zoom controls */}
      <div className="absolute bottom-3 left-3 flex flex-col overflow-hidden rounded-lg border border-line bg-card">
        <Ctl onClick={() => zoom(1.2)}><Plus size={14} /></Ctl>
        <Ctl onClick={() => zoom(0.83)} border><Minus size={14} /></Ctl>
        <Ctl onClick={reset} border><Maximize2 size={13} /></Ctl>
      </div>
    </div>
  );
}

/* ── radial layout ──────────────────────────────────────────────────────────
   Standard radial dendrogram: leaves get equal angular slots, internal nodes
   centre over their children, radius grows with depth. The outer radius grows
   with the leaf count (MIN_ARC floor) so leaves never crowd; the whole cloud is
   then fit to the stage. */
interface Layout { nodes: TreeNode[]; links: [TreeNode, TreeNode][]; fit: number }

function radialLayout(root: TreeNode, collapsed: Set<string>, hasMatch: Set<string>): Layout {
  const isOpen = (n: TreeNode) => n.children.length > 0 && (!collapsed.has(n.id) || hasMatch.has(n.id));

  let totalLeaves = 0;
  const countL = (n: TreeNode) => { if (isOpen(n)) n.children.forEach(countL); else totalLeaves++; };
  countL(root);
  totalLeaves = Math.max(1, totalLeaves);

  const nodes: TreeNode[] = [];
  const links: [TreeNode, TreeNode][] = [];
  let li = 0, maxDepth = 0;
  const assign = (n: TreeNode, depth: number, parent: TreeNode | null) => {
    n.depth = depth; if (depth > maxDepth) maxDepth = depth;
    nodes.push(n);
    if (parent) links.push([parent, n]);
    if (isOpen(n)) {
      n.children.forEach((c) => assign(c, depth + 1, n));
      n.angle = (n.children[0].angle! + n.children[n.children.length - 1].angle!) / 2;
    } else {
      n.angle = ((li + 0.5) / totalLeaves) * Math.PI * 2;
      li++;
    }
  };
  assign(root, 0, null);

  const outerR = Math.max(maxDepth * RING, (totalLeaves * MIN_ARC) / (2 * Math.PI));
  const ringR = (d: number) => (maxDepth === 0 ? 0 : (outerR * d) / maxDepth);

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const n of nodes) {
    const rr = ringR(n.depth!);
    const a = n.angle! - Math.PI / 2;
    n.x = Math.cos(a) * rr;
    n.y = Math.sin(a) * rr;
    n.r = nodeRadius(n);
    minX = Math.min(minX, n.x - n.r); maxX = Math.max(maxX, n.x + n.r);
    minY = Math.min(minY, n.y - n.r); maxY = Math.max(maxY, n.y + n.r);
  }
  const cx0 = (minX + maxX) / 2, cy0 = (minY + maxY) / 2;
  const fit = Math.min((STAGE_W - PAD * 2) / Math.max(1, maxX - minX), (STAGE_H - PAD * 2) / Math.max(1, maxY - minY), 1.1);
  for (const n of nodes) {
    n.x = (n.x! - cx0) * fit;
    n.y = (n.y! - cy0) * fit;
    n.r = Math.max(2, n.r! * fit);
  }
  return { nodes, links, fit };
}

function nodeRadius(n: TreeNode): number {
  if (n.kind === "root") return 15;
  if (n.kind === "domain" || n.kind === "bucket") return 6 + Math.min(6, Math.log2(n.hostCount + 1) * 1.5);
  const boost = Math.min(n.findings, 5) * 0.8 + (n.risk === "high" ? 2.4 : n.risk === "elevated" ? 1.2 : 0);
  return 4.2 + boost;
}

function nodeFill(n: TreeNode): { fill: string; stroke: string; sw: number; dash?: string } {
  if (n.kind === "root") return { fill: "rgb(var(--brand))", stroke: "rgb(var(--card2))", sw: 1.5 };
  if (n.kind === "bucket") return { fill: "rgb(var(--card))", stroke: ink(0.34), sw: 1.2, dash: "2 2" };
  if (n.kind === "domain") return { fill: "rgb(var(--card2))", stroke: ink(0.38), sw: 1.2 };
  if (n.scope === "out") return { fill: "transparent", stroke: ink(0.24), sw: 1, dash: "3 3" };
  const c = COVERAGE[n.coverage ?? "untested"].color;
  if (n.coverage === "untested") return { fill: "rgb(var(--card))", stroke: c, sw: 1.4 };
  return { fill: c, stroke: "rgb(var(--card2))", sw: 1 };
}

/** Label by default: the structural nodes + notable hosts. Plain hosts reveal on hover. */
function labelByDefault(n: TreeNode): boolean {
  if (n.kind === "root" || n.kind === "domain" || n.kind === "bucket") return true;
  return n.risk !== "none" || n.findings > 0;
}

function labelText(n: TreeNode): string {
  if (n.kind === "root") return n.label;
  const base = n.kind === "host" ? shortHost(n.full || n.label) : n.label;
  if ((n.kind === "domain" || n.kind === "bucket") && n.hostCount > 1) return `${base} ·${n.hostCount}`;
  return base;
}

function NodeLabel({ n }: { n: TreeNode }) {
  if (n.kind === "root") {
    return (
      <text x={n.x} y={n.y! + n.r! + 13} textAnchor="middle" fontSize={11}
            paintOrder="stroke" stroke="rgb(var(--card2))" strokeWidth={3.5} strokeLinejoin="round"
            fill={ink(0.9)} style={{ fontWeight: 700 }}>
        {labelText(n)}
      </text>
    );
  }
  // radial label reading outward, flipped on the left half so it's never upside down
  const ang = Math.atan2(n.y!, n.x!);
  const deg = (ang * 180) / Math.PI;
  const flip = deg > 90 || deg < -90;
  const rot = flip ? deg + 180 : deg;
  const anchor = flip ? "end" : "start";
  const ox = Math.cos(ang) * (n.r! + 4), oy = Math.sin(ang) * (n.r! + 4);
  return (
    <text transform={`translate(${n.x! + ox} ${n.y! + oy}) rotate(${rot})`} textAnchor={anchor} dominantBaseline="middle"
          fontSize={9.5} paintOrder="stroke" stroke="rgb(var(--card2))" strokeWidth={3} strokeLinejoin="round"
          fill={ink(0.82)} style={{ fontWeight: n.kind === "host" ? 500 : 600 }}>
      {labelText(n)}
    </text>
  );
}

/* ── tooltip ────────────────────────────────────────────────────────────── */
function HoverCard({ n, open, collapsedState, left, top, containerW }: {
  n: TreeNode; open: number; collapsedState: boolean; left: number; top: number; containerW: number;
}) {
  const branch = n.children.length > 0;
  return (
    <div className="pointer-events-none absolute z-20 -translate-x-1/2 -translate-y-full"
         style={{ left: clamp(left, 90, containerW - 90), top: top - 8 }}>
      <div className="rounded-lg border border-line bg-card/95 px-2.5 py-1.5 text-xs shadow-lg backdrop-blur">
        <div className="flex items-center gap-1.5 font-semibold text-fg">
          <KindIcon kind={n.kind} /><span className="max-w-[260px] truncate">{n.full || n.label}</span>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px] text-muted">
          {n.kind === "host" ? (
            <>
              <span className="inline-flex items-center gap-1">
                <i className="h-2 w-2 rounded-full" style={coverDot(n)} />
                {n.scope === "out" ? "Out of scope" : COVERAGE[n.coverage ?? "untested"].label}
              </span>
              {open > 0 && <span>{open} open port{open === 1 ? "" : "s"}</span>}
              {n.findings > 0 && <span className="text-fg">{n.findings} finding{n.findings === 1 ? "" : "s"}</span>}
            </>
          ) : (
            <>
              <span>{n.hostCount} host{n.hostCount === 1 ? "" : "s"}</span>
              {n.findings > 0 && <span className="text-fg">{n.findings} finding{n.findings === 1 ? "" : "s"}</span>}
            </>
          )}
          {n.risk !== "none" && (
            <span className="inline-flex items-center gap-1 font-medium" style={{ color: RISK_COLOR[n.risk] }}>
              <ShieldAlert size={11} />{n.risk === "high" ? "High risk" : "Elevated"}
            </span>
          )}
          {branch && <span className="text-muted/80">· {collapsedState ? "click to expand" : "click to collapse"}</span>}
        </div>
      </div>
    </div>
  );
}

/* ── chrome ─────────────────────────────────────────────────────────────── */
function Ctl({ onClick, border, children }: { onClick: () => void; border?: boolean; children: React.ReactNode }) {
  return (
    <button onMouseDown={(e) => e.stopPropagation()} onClick={onClick}
      className={`grid h-8 w-8 place-items-center text-muted transition hover:bg-card2 hover:text-fg ${border ? "border-t border-line" : ""}`}>
      {children}
    </button>
  );
}
function Swatch({ label, style }: { label: string; style: React.CSSProperties }) {
  return <span className="flex items-center gap-1.5"><span className="h-3 w-3 shrink-0 rounded-full" style={style} />{label}</span>;
}
function Stat({ value, label, tone }: { value: string; label: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-line bg-card/85 px-2.5 py-1 text-right backdrop-blur">
      <div className="text-sm font-semibold leading-none" style={tone ? { color: tone } : undefined}>{value}</div>
      <div className="mt-0.5 text-[10px] uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}
function KindIcon({ kind }: { kind: TreeNode["kind"] }) {
  const I = kind === "bucket" ? Folder : kind === "root" || kind === "domain" ? Network : Globe;
  return <I size={12} className="shrink-0 text-muted" />;
}

/* ── visuals ────────────────────────────────────────────────────────────── */
function coverDot(n: TreeNode): React.CSSProperties {
  if (n.scope === "out") return { background: "transparent", border: "1.5px dashed rgb(var(--fg) / 0.3)" };
  if ((n.coverage ?? "untested") === "untested") return { background: "rgb(var(--card))", border: `1.5px solid ${COVERAGE.untested.color}` };
  return { background: COVERAGE[n.coverage!].color };
}
function shortHost(h: string): string {
  const base = h.split(":")[0];
  return base.length > 26 ? base.slice(0, 25) + "…" : base;
}

/** Classic radial link: control points sit at the mid-radius along each endpoint's angle. */
function linkPath(s: TreeNode, t: TreeNode): string {
  const sr = Math.hypot(s.x!, s.y!), tr = Math.hypot(t.x!, t.y!);
  const ta = Math.atan2(t.y!, t.x!);
  const sa = sr < 1 ? ta : Math.atan2(s.y!, s.x!); // root at centre → straight spoke
  const mr = (sr + tr) / 2;
  const c1x = Math.cos(sa) * mr, c1y = Math.sin(sa) * mr;
  const c2x = Math.cos(ta) * mr, c2y = Math.sin(ta) * mr;
  return `M${s.x},${s.y}C${c1x},${c1y} ${c2x},${c2y} ${t.x},${t.y}`;
}
