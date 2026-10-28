"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Globe, Server, Network, Link2, Plus, Minus, Maximize2, Search, ShieldAlert, X } from "lucide-react";
import type { Asset, AssetKind, Service, Finding } from "@/lib/types";
import { COVERAGE, SEVERITY, ink } from "@/lib/theme";
import { cx, assetHosts } from "@/lib/format";
import { packSiblings } from "@/lib/pack";

/* ───────────────────────────────────────────────────────────────────────────
   Asset coverage map — a packed-bubble "constellation".

   The old force-directed layout was O(N²)·iterations and collapsed into an
   unreadable hairball past ~100 nodes (a real engagement has 700+ live hosts).
   This lays every host out in O(N) with a deterministic phyllotaxis (sunflower)
   packing, groups hosts under their scope apex, sorts the risky few to the core
   so they read first, and labels only what matters — the rest stay as dots you
   reveal on hover / search / zoom. Scales to thousands and stays legible.
   ──────────────────────────────────────────────────────────────────────────── */

type RiskLevel = "high" | "elevated" | "none";
interface PNode {
  id: string; host: string; kind: AssetKind; scope: "in" | "out";
  coverage: Asset["coverage"]; findings: number; ports: number; risk: RiskLevel;
  r: number; x: number; y: number;
  lead?: boolean; // the one most-severe node in its group — labelled by default
}
interface PGroup { key: string; label: string; cx: number; cy: number; r: number; count: number }

const STAGE_W = 1040, STAGE_H = 560, PAD = 54;
const GOLDEN = Math.PI * (3 - Math.sqrt(5)); // 137.5° — spiral for placing GROUP hulls
const NODE_GAP = 4;                          // padding added to each node radius when packing
const clamp = (n: number, a: number, b: number) => Math.max(a, Math.min(b, n));
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const HOST_KINDS = new Set<AssetKind>(["domain", "subdomain", "ip", "cidr"]);
const RISK_RANK: Record<RiskLevel, number> = { high: 2, elevated: 1, none: 0 };
const RISK_COLOR = { high: "#ef4444", elevated: "#f59e0b" } as const;

export function AssetMap({
  assets, orgName, services = [], findings = [], onSelectHost, selectedHost,
}: { assets: Asset[]; orgName: string; services?: Service[]; findings?: Finding[]; onSelectHost?: (host: string) => void; selectedHost?: string }) {
  // per-host risk posture: worst finding severity + service posture (exposed/outdated) + open ports
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
    const m = new Map<string, { level: RiskLevel; open: number }>();
    new Set<string>([...agg.keys(), ...sev.keys()]).forEach((h) => {
      const a = agg.get(h) ?? { open: 0, exposed: false, outdated: false };
      const r = sev.get(h) ?? 0;
      const level: RiskLevel = a.exposed || r >= 4 ? "high" : a.outdated || r >= 1 ? "elevated" : "none";
      m.set(h, { level, open: a.open });
    });
    return m;
  }, [services, findings]);

  const { nodes, groups } = useMemo(
    () => buildConstellation(assets, orgName, hostRisk),
    [assets, orgName, hostRisk],
  );

  const totals = useMemo(() => {
    const t = { hosts: nodes.length, tested: 0, untested: 0, inprog: 0, out: 0, high: 0, elevated: 0 };
    for (const n of nodes) {
      if (n.scope === "out") t.out++;
      else if (n.coverage === "tested") t.tested++;
      else if (n.coverage === "in-progress") t.inprog++;
      else t.untested++;
      if (n.risk === "high") t.high++;
      else if (n.risk === "elevated") t.elevated++;
    }
    return t;
  }, [nodes]);

  const [view, setView] = useState({ tx: 0, ty: 0, s: 1 });
  const [dragging, setDragging] = useState(false);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"all" | "risk" | "untested">("all");
  const [hover, setHover] = useState<{ id: string; left: number; top: number } | null>(null);
  const dragRef = useRef<{ x: number; y: number; tx: number; ty: number; moved: boolean } | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const q = query.trim().toLowerCase();
  const isActive = (n: PNode) => {
    if (filter === "risk" && n.risk === "none") return false;
    if (filter === "untested" && !(n.coverage === "untested" || n.scope === "out")) return false;
    if (q && !n.host.toLowerCase().includes(q)) return false;
    return true;
  };

  // wheel zoom (non-passive so we can preventDefault the page scroll)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      setView((v) => ({ ...v, s: clamp(v.s * (e.deltaY < 0 ? 1.12 : 0.89), 0.5, 6) }));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const onDown = (e: React.MouseEvent) => { dragRef.current = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty, moved: false }; setDragging(true); };
  const onMove = (e: React.MouseEvent) => {
    const d = dragRef.current; if (!d) return;
    if (Math.abs(e.clientX - d.x) + Math.abs(e.clientY - d.y) > 3) d.moved = true;
    setView((v) => ({ ...v, tx: d.tx + (e.clientX - d.x), ty: d.ty + (e.clientY - d.y) }));
  };
  const onUp = () => { dragRef.current = null; setDragging(false); };
  const zoom = (f: number) => setView((v) => ({ ...v, s: clamp(v.s * f, 0.5, 6) }));
  const reset = () => setView({ tx: 0, ty: 0, s: 1 });

  const hostOfNode = (n: PNode) => n.host;
  const enter = (e: React.MouseEvent, n: PNode) => {
    const c = containerRef.current?.getBoundingClientRect();
    const b = (e.currentTarget as SVGElement).getBoundingClientRect();
    if (!c) return;
    setHover({ id: n.id, left: b.left + b.width / 2 - c.left, top: b.top - c.top });
  };
  const hovered = hover ? nodes.find((n) => n.id === hover.id) : undefined;
  const selectedNode = selectedHost ? nodes.find((n) => n.host === selectedHost) : undefined;

  // static node layer — memoised so hover/tooltip never re-renders 700 circles
  const nodeLayer = useMemo(() => (
    <>
      {nodes.map((n) => {
        const act = isActive(n);
        const v = nodeVisual(n);
        const op = act ? 1 : 0.1;
        // label only the group's lead (single most-severe host) by default so the dense
        // risk core stays legible; every other node reveals its label on hover / search.
        const show = act && (n.lead || (!!q && n.host.toLowerCase().includes(q)));
        return (
          <g key={n.id} opacity={op} style={{ transition: "opacity .18s ease" }}
             className={onSelectHost ? "cursor-pointer" : undefined}
             onMouseDown={(e) => e.stopPropagation()}
             onMouseEnter={(e) => enter(e, n)} onMouseLeave={() => setHover(null)}
             onClick={onSelectHost && act ? () => onSelectHost(hostOfNode(n)) : undefined}>
            {n.risk !== "none" && act && (
              <circle cx={n.x} cy={n.y} r={n.r + 6} fill={RISK_COLOR[n.risk]} opacity={0.16} />
            )}
            <circle cx={n.x} cy={n.y} r={n.r} fill={v.fill} stroke={v.stroke} strokeWidth={v.strokeW} strokeDasharray={v.dash} />
            {n.risk !== "none" && (
              <circle cx={n.x} cy={n.y} r={n.r + 2.3} fill="none" stroke={RISK_COLOR[n.risk]} strokeWidth={2} />
            )}
            {show && <NodeLabel n={n} />}
          </g>
        );
      })}
    </>
  ), [nodes, filter, q, onSelectHost]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div
      ref={containerRef}
      className="graph-grid relative h-[560px] select-none overflow-hidden rounded-xl border border-line bg-card2"
      style={{ cursor: dragging ? "grabbing" : "grab" }}
      onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={() => { onUp(); setHover(null); }}
    >
      <svg width="100%" height="100%" viewBox={`0 0 ${STAGE_W} ${STAGE_H}`} preserveAspectRatio="xMidYMid meet" className="block">
        <g transform={`translate(${STAGE_W / 2 + view.tx} ${STAGE_H / 2 + view.ty}) scale(${view.s})`}>
          {/* group hulls */}
          {groups.map((g) => (
            <g key={g.key} opacity={0.9}>
              <circle cx={g.cx} cy={g.cy} r={g.r} fill={ink(0.025)} stroke={ink(0.09)} strokeWidth={1} />
              {groups.length > 1 && (
                <text x={g.cx} y={g.cy - g.r - 7} textAnchor="middle" fontSize={11}
                      paintOrder="stroke" stroke="rgb(var(--card2))" strokeWidth={3.5} strokeLinejoin="round"
                      fill={ink(0.6)} style={{ fontWeight: 600 }}>
                  {g.label} · {g.count}
                </text>
              )}
            </g>
          ))}

          {nodeLayer}

          {/* selected ring + label (overlay, not in memoised layer) */}
          {selectedNode && (
            <g pointerEvents="none">
              <circle cx={selectedNode.x} cy={selectedNode.y} r={selectedNode.r + 4.5} fill="none"
                      stroke={ink(0.9)} strokeWidth={2} />
              {!selectedNode.lead && <NodeLabel n={selectedNode} />}
            </g>
          )}
          {/* hovered emphasis — reveal the label for any non-lead node */}
          {hovered && (
            <g pointerEvents="none">
              <circle cx={hovered.x} cy={hovered.y} r={hovered.r + 3.5} fill="none" stroke={ink(0.55)} strokeWidth={1.5} />
              {!hovered.lead && <NodeLabel n={hovered} />}
            </g>
          )}
        </g>
      </svg>

      {/* tooltip */}
      {hover && hovered && (
        <div className="pointer-events-none absolute z-20 -translate-x-1/2 -translate-y-full"
             style={{ left: clamp(hover.left, 90, (containerRef.current?.clientWidth ?? STAGE_W) - 90), top: hover.top - 8 }}>
          <div className="rounded-lg border border-line bg-card/95 px-2.5 py-1.5 text-xs shadow-lg backdrop-blur">
            <div className="flex items-center gap-1.5 font-semibold text-fg">
              <KindIcon kind={hovered.kind} /><span className="max-w-[240px] truncate">{hovered.host}</span>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px] text-muted">
              <span className="inline-flex items-center gap-1">
                <i className="h-2 w-2 rounded-full" style={coverDot(hovered)} />
                {hovered.scope === "out" ? "Out of scope" : COVERAGE[hovered.coverage].label}
              </span>
              {hovered.ports > 0 && <span>{hovered.ports} open port{hovered.ports === 1 ? "" : "s"}</span>}
              {hovered.findings > 0 && <span className="text-fg">{hovered.findings} finding{hovered.findings === 1 ? "" : "s"}</span>}
              {hovered.risk !== "none" && (
                <span className="inline-flex items-center gap-1 font-medium" style={{ color: RISK_COLOR[hovered.risk] }}>
                  <ShieldAlert size={11} />{hovered.risk === "high" ? "High risk" : "Elevated"}
                </span>
              )}
            </div>
          </div>
        </div>
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
            {([["all", `All ${totals.hosts}`], ["risk", `Risk ${totals.high + totals.elevated}`], ["untested", `Untested ${totals.untested + totals.out}`]] as const).map(([k, label], i) => (
              <button key={k} onMouseDown={(e) => e.stopPropagation()} onClick={() => setFilter(k)}
                className={cx("px-2.5 py-1 text-xs transition", i > 0 && "border-l border-line",
                  filter === k ? "bg-fg/10 font-medium text-fg" : "text-muted hover:text-fg")}>
                {label}
              </button>
            ))}
          </div>
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
          <Swatch label="Out of scope" style={{ background: "transparent", border: "1.5px dashed rgb(var(--fg) / 0.3)" }} />
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
function KindIcon({ kind }: { kind: AssetKind }) {
  const I = kind === "ip" || kind === "cidr" ? Server : kind === "service" ? Network : kind === "endpoint" ? Link2 : Globe;
  return <I size={12} className="shrink-0 text-muted" />;
}

/* ── visuals ────────────────────────────────────────────────────────────── */
function nodeVisual(n: PNode): { fill: string; stroke: string; strokeW: number; dash?: string } {
  if (n.scope === "out") return { fill: "transparent", stroke: ink(0.24), strokeW: 1, dash: "3 3" };
  const c = COVERAGE[n.coverage].color;
  if (n.coverage === "untested") return { fill: "rgb(var(--card))", stroke: c, strokeW: 1.5 };
  return { fill: c, stroke: "rgb(var(--card2))", strokeW: 1 }; // filled + surface ring to separate overlapping marks
}
function coverDot(n: PNode): React.CSSProperties {
  if (n.scope === "out") return { background: "transparent", border: "1.5px dashed rgb(var(--fg) / 0.3)" };
  if (n.coverage === "untested") return { background: "rgb(var(--card))", border: `1.5px solid ${COVERAGE.untested.color}` };
  return { background: COVERAGE[n.coverage].color };
}
function shortHost(h: string): string {
  const base = h.split(":")[0];
  return base.length > 22 ? base.slice(0, 21) + "…" : base;
}
function NodeLabel({ n }: { n: PNode }) {
  return (
    <text x={n.x} y={n.y + n.r + 9.5} textAnchor="middle" fontSize={9.5}
          paintOrder="stroke" stroke="rgb(var(--card2))" strokeWidth={3} strokeLinejoin="round"
          fill={ink(0.82)} style={{ fontWeight: 500 }}>
      {shortHost(n.host)}
    </text>
  );
}

/* ── layout: group by scope apex, pack each group with phyllotaxis (O(N)) ─── */
function buildConstellation(
  assets: Asset[], orgName: string, risk: Map<string, { level: RiskLevel; open: number }>,
): { nodes: PNode[]; groups: PGroup[] } {
  const base = (orgName || "").replace(/^\*\./, "").toLowerCase();
  const groupKey = (host: string): string => {
    const h = host.split(":")[0].toLowerCase();
    if (IP_RE.test(h)) return "ip";
    if (base && (h === base || h.endsWith("." + base))) return base;
    const p = h.split(".");
    return p.length <= 2 ? h : p.slice(-2).join(".");
  };
  const groupLabel = (key: string) => (key === "ip" ? "IP space" : key);

  // collect host-like assets, attach risk + sizing
  const items = assets
    .filter((a) => HOST_KINDS.has(a.kind))
    .map((a) => {
      const r = risk.get(a.value) ?? { level: "none" as RiskLevel, open: 0 };
      const boost = Math.min(a.findings, 5) * 0.9 + (r.level === "high" ? 2.4 : r.level === "elevated" ? 1.2 : 0);
      return {
        id: a.id, host: a.value, kind: a.kind, scope: a.scope, coverage: a.coverage,
        findings: a.findings, ports: r.open, risk: r.level, r: 4.6 + boost, _g: groupKey(a.value),
      };
    });

  // bucket into groups
  const buckets = new Map<string, typeof items>();
  for (const it of items) (buckets.get(it._g) ?? buckets.set(it._g, []).get(it._g)!).push(it);

  // pack each group with real circle packing (no overlaps, whatever the size spread);
  // risky/notable sorted first so they land at the core and read first. We pad each
  // radius by NODE_GAP before packing so the risk ring/glow and a little breathing room
  // clear too, then recentre on the cluster's bounding box.
  const localGroups = [...buckets.entries()].map(([key, arr]) => {
    arr.sort((a, b) =>
      RISK_RANK[b.risk] - RISK_RANK[a.risk] || b.findings - a.findings ||
      (b.scope === "in" ? 0 : 1) - (a.scope === "in" ? 0 : 1) || a.host.localeCompare(b.host));
    const pos = packSiblings(arr.map((it) => it.r + NODE_GAP));
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    arr.forEach((it, i) => {
      minX = Math.min(minX, pos[i].x - it.r); maxX = Math.max(maxX, pos[i].x + it.r);
      minY = Math.min(minY, pos[i].y - it.r); maxY = Math.max(maxY, pos[i].y + it.r);
    });
    const mx = (minX + maxX) / 2, my = (minY + maxY) / 2;
    let rad = 0;
    const packed = arr.map((it, i) => {
      const x = pos[i].x - mx, y = pos[i].y - my;
      rad = Math.max(rad, Math.hypot(x, y) + it.r);
      return { ...it, x, y };
    });
    return { key, label: groupLabel(key), r: rad + 14, count: arr.length, packed };
  });

  // place groups: largest first at centre, others spiralled out with collision avoidance
  localGroups.sort((a, b) => b.r - a.r);
  const placed: PGroup[] = [];
  const maxR = localGroups[0]?.r ?? 1;
  for (const g of localGroups) {
    let cx = 0, cy = 0;
    for (let k = 0; k < 4000; k++) {
      const d = maxR * 0.9 * Math.sqrt(k);
      const ang = k * GOLDEN;
      cx = Math.cos(ang) * d; cy = Math.sin(ang) * d;
      if (placed.every((p) => Math.hypot(p.cx - cx, p.cy - cy) >= p.r + g.r + 26)) break;
    }
    placed.push({ key: g.key, label: g.label, cx, cy, r: g.r, count: g.count });
  }
  const byKey = new Map(placed.map((p) => [p.key, p]));

  // emit world-space nodes, then fit the whole cloud to the stage (centred at 0,0)
  const nodes: PNode[] = [];
  for (const g of localGroups) {
    const p = byKey.get(g.key)!;
    // packed is sorted risk-first, so the first notable host is the group's lead —
    // the only one labelled by default; the rest reveal their label on hover/selection.
    const leadId = g.packed.find((it) => it.risk !== "none" || it.findings > 0)?.id;
    for (const it of g.packed) {
      const { _g, ...rest } = it;
      nodes.push({ ...rest, x: p.cx + it.x, y: p.cy + it.y, lead: it.id === leadId });
    }
  }
  if (!nodes.length) return { nodes, groups: [] };

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const p of placed) { minX = Math.min(minX, p.cx - p.r); maxX = Math.max(maxX, p.cx + p.r); minY = Math.min(minY, p.cy - p.r); maxY = Math.max(maxY, p.cy + p.r); }
  const cx0 = (minX + maxX) / 2, cy0 = (minY + maxY) / 2;
  const fit = Math.min((STAGE_W - PAD * 2) / Math.max(1, maxX - minX), (STAGE_H - PAD * 2) / Math.max(1, maxY - minY), 1.5);
  for (const n of nodes) { n.x = (n.x - cx0) * fit; n.y = (n.y - cy0) * fit; n.r *= fit; }
  const groups = placed.map((p) => ({ ...p, cx: (p.cx - cx0) * fit, cy: (p.cy - cy0) * fit, r: p.r * fit }));
  return { nodes, groups };
}
