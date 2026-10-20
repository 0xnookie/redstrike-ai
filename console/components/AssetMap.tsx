"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Building2, Globe, Server, Network, Radio, Link2, Plus, Minus, Maximize2, type LucideIcon } from "lucide-react";
import type { Asset, AssetKind, Service } from "@/lib/types";
import { COVERAGE } from "@/lib/theme";
import { cx } from "@/lib/format";

type NodeKind = AssetKind | "org";
interface GNode {
  id: string; label: string; kind: NodeKind; scope: "in" | "out";
  coverage: Asset["coverage"]; findings: number; r: number; x: number; y: number;
}
interface GEdge { a: string; b: string; }

const KIND_ICON: Record<NodeKind, LucideIcon> = {
  org: Building2, domain: Globe, subdomain: Globe, ip: Server, cidr: Network, service: Radio, endpoint: Link2,
};
const KIND_LABEL: [NodeKind, string][] = [
  ["org", "Org"], ["domain", "Domain"], ["subdomain", "Subdomain"], ["ip", "IP"], ["service", "Service"], ["endpoint", "Endpoint"],
];

const STAGE_W = 920, STAGE_H = 520;
const clamp = (n: number, a: number, b: number) => Math.max(a, Math.min(b, n));
const baseR = (k: NodeKind) =>
  k === "org" ? 28 : k === "domain" ? 23 : k === "subdomain" ? 20 : k === "ip" || k === "cidr" ? 18 : k === "service" ? 16 : 15;

export function AssetMap({ assets, orgName, services = [], onSelectHost, selectedHost }: { assets: Asset[]; orgName: string; services?: Service[]; onSelectHost?: (host: string) => void; selectedHost?: string }) {
  const { nodes, edges } = useMemo(() => buildGraph(assets, orgName), [assets, orgName]);
  const positioned = useMemo(() => layout(nodes, edges), [nodes, edges]);

  // open-port risk per host (from host discovery): exposed/findings → high, outdated/finding → elevated
  const hostRisk = useMemo(() => {
    const agg = new Map<string, { findings: number; open: number; exposed: boolean; outdated: boolean }>();
    for (const s of services) {
      if (s.flagged === "out-of-scope") continue;
      const a = agg.get(s.host) ?? { findings: 0, open: 0, exposed: false, outdated: false };
      a.findings += s.findings ?? 0;
      if (s.state === "open") a.open += 1;
      if (s.flagged === "exposed") a.exposed = true;
      if (s.flagged === "outdated") a.outdated = true;
      agg.set(s.host, a);
    }
    const m = new Map<string, { level: "high" | "medium" | "low"; open: number }>();
    agg.forEach((a, host) =>
      m.set(host, { level: a.exposed || a.findings >= 5 ? "high" : a.outdated || a.findings >= 1 ? "medium" : "low", open: a.open })
    );
    return m;
  }, [services]);

  const [view, setView] = useState({ tx: 0, ty: 0, s: 1 });
  const dragRef = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // wheel zoom (registered non-passive so we can preventDefault the page scroll)
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      setView((v) => ({ ...v, s: clamp(v.s * (e.deltaY < 0 ? 1.12 : 0.89), 0.45, 2.8) }));
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
  const zoom = (f: number) => setView((v) => ({ ...v, s: clamp(v.s * f, 0.45, 2.8) }));

  return (
    <div
      ref={containerRef}
      className="graph-grid relative h-[520px] select-none overflow-hidden rounded-xl border border-line bg-card2"
      style={{ cursor: dragging ? "grabbing" : "grab" }}
      onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={onUp}
    >
      <div
        className="absolute left-1/2 top-1/2"
        style={{ width: STAGE_W, height: STAGE_H, transform: `translate(-50%,-50%) translate(${view.tx}px,${view.ty}px) scale(${view.s})` }}
      >
        <svg width={STAGE_W} height={STAGE_H} className="absolute inset-0" style={{ pointerEvents: "none" }}>
          {edges.map((e, i) => {
            const a = positioned[e.a], b = positioned[e.b];
            if (!a || !b) return null;
            return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="rgb(var(--fg) / 0.14)" strokeWidth={1.2} />;
          })}
        </svg>
        {Object.values(positioned).map((n) => {
          const Icon = KIND_ICON[n.kind];
          const st = nodeStyle(n);
          const hk = n.kind === "subdomain" || n.kind === "ip" || n.kind === "domain" || n.kind === "service" ? n.label.split(":")[0] : undefined;
          const risk = hk ? hostRisk.get(hk) : undefined;
          const ringColor = risk && risk.level !== "low" ? (risk.level === "high" ? "#ef4444" : "#f59e0b") : undefined;
          const showPorts = !!risk && risk.open > 0 && (n.kind === "subdomain" || n.kind === "ip" || n.kind === "domain");
          const clickable = !!hk && !!onSelectHost;
          const selected = !!hk && hk === selectedHost;
          const ringParts: string[] = [];
          if (ringColor) ringParts.push("0 0 0 2.5px rgb(var(--card2))", `0 0 0 5px ${ringColor}`);
          if (selected) { const g = ringColor ? 7 : 2.5, o = ringColor ? 9.5 : 5; ringParts.push(`0 0 0 ${g}px rgb(var(--card2))`, `0 0 0 ${o}px rgb(var(--fg))`); }
          return (
            <div
              key={n.id}
              className={cx("group absolute flex flex-col items-center", clickable && "cursor-pointer")}
              style={{ left: n.x, top: n.y, transform: "translate(-50%,-50%)" }}
              onMouseDown={clickable ? (e) => e.stopPropagation() : undefined}
              onClick={clickable ? () => onSelectHost!(hk!) : undefined}
              title={hk}
            >
              <div
                className={cx("relative grid place-items-center rounded-full transition-transform", clickable && "group-hover:scale-110", selected && "scale-110")}
                style={{ width: n.r * 2, height: n.r * 2, background: st.bg, border: st.border, color: st.icon, boxShadow: ringParts.length ? ringParts.join(", ") : undefined }}
              >
                <Icon size={Math.round(n.r * 0.85)} strokeWidth={1.75} />
                {showPorts && (
                  <span className="absolute -right-1.5 -top-1.5 grid h-[17px] min-w-[17px] place-items-center rounded-full border border-line bg-card px-1 text-[9px] font-semibold text-fg">
                    {risk!.open}
                  </span>
                )}
              </div>
              <div
                className="mt-1 max-w-[130px] truncate text-center text-[11px] font-medium"
                style={{ color: st.label, textDecoration: n.scope === "out" ? "line-through" : "none" }}
              >
                {n.label}
              </div>
            </div>
          );
        })}
      </div>

      {/* legend */}
      <div className="absolute left-3 top-3 w-56 rounded-xl border border-line bg-card/85 p-3 text-xs backdrop-blur">
        <div className="mb-2 font-semibold">Asset coverage map</div>
        <div className="mb-2 grid grid-cols-2 gap-x-3 gap-y-1 text-muted">
          {KIND_LABEL.map(([k, l]) => {
            const I = KIND_ICON[k];
            return <span key={k} className="flex items-center gap-1.5"><I size={12} />{l}</span>;
          })}
        </div>
        <div className="space-y-1 border-t border-line pt-2 text-muted">
          <Swatch label="Tested" style={{ background: COVERAGE.tested.color }} />
          <Swatch label="In progress" style={{ background: COVERAGE["in-progress"].color }} />
          <Swatch label="Untested" style={{ background: "rgb(var(--card))", border: `1.5px solid ${COVERAGE.untested.color}` }} />
          <Swatch label="Out of scope" style={{ background: "transparent", border: "1.5px dashed rgb(var(--fg) / 0.3)" }} />
        </div>
        <div className="mt-2 space-y-1 border-t border-line pt-2 text-muted">
          <div className="mb-0.5 text-[10px] font-medium uppercase tracking-wide">Open-port risk</div>
          <Swatch label="High — exposed / findings" style={{ background: "transparent", border: "2px solid #ef4444" }} />
          <Swatch label="Elevated — outdated" style={{ background: "transparent", border: "2px solid #f59e0b" }} />
          <div className="flex items-center gap-2"><span className="grid h-3.5 w-3.5 place-items-center rounded-full border border-line bg-card text-[7px] font-semibold text-fg">n</span>open ports</div>
        </div>
        <p className="mt-2 border-t border-line pt-2 text-[10px] text-muted">Force-directed · drag to pan, scroll to zoom · click a host to filter ports.</p>
      </div>

      {/* zoom controls */}
      <div className="absolute bottom-3 left-3 flex flex-col overflow-hidden rounded-lg border border-line bg-card">
        <Ctl onClick={() => zoom(1.15)}><Plus size={14} /></Ctl>
        <Ctl onClick={() => zoom(0.87)} border><Minus size={14} /></Ctl>
        <Ctl onClick={() => setView({ tx: 0, ty: 0, s: 1 })} border><Maximize2 size={13} /></Ctl>
      </div>
    </div>
  );
}

function Ctl({ onClick, border, children }: { onClick: () => void; border?: boolean; children: React.ReactNode }) {
  return (
    <button
      onMouseDown={(e) => e.stopPropagation()}
      onClick={onClick}
      className={`grid h-8 w-8 place-items-center text-muted transition hover:bg-card2 hover:text-fg ${border ? "border-t border-line" : ""}`}
    >
      {children}
    </button>
  );
}
function Swatch({ label, style }: { label: string; style: React.CSSProperties }) {
  return <div className="flex items-center gap-2"><span className="h-3 w-3 shrink-0 rounded-full" style={style} />{label}</div>;
}

function nodeStyle(n: GNode): { bg: string; border: string; icon: string; label: string } {
  if (n.kind === "org") return { bg: "transparent", border: "1.5px dashed rgb(var(--fg) / 0.32)", icon: "rgb(var(--fg) / 0.7)", label: "rgb(var(--fg))" };
  if (n.scope === "out") return { bg: "transparent", border: "1.5px dashed rgb(var(--fg) / 0.22)", icon: "rgb(var(--fg) / 0.32)", label: "rgb(var(--fg) / 0.45)" };
  const c = COVERAGE[n.coverage].color;
  if (n.coverage === "untested") return { bg: "rgb(var(--card))", border: `1.5px solid ${c}`, icon: c, label: "rgb(var(--fg) / 0.72)" };
  return { bg: c, border: "none", icon: "#ffffff", label: "rgb(var(--fg))" }; // tested / in-progress = filled
}

function buildGraph(assets: Asset[], orgName: string): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  const ORG = "__org";
  nodes.push({ id: ORG, label: orgName, kind: "org", scope: "in", coverage: "tested", findings: 0, r: baseR("org"), x: 0, y: 0 });
  assets.forEach((a) =>
    nodes.push({
      id: a.id, label: a.value, kind: a.kind, scope: a.scope, coverage: a.coverage,
      findings: a.findings, r: baseR(a.kind) + Math.min(a.findings, 6) * 1.4, x: 0, y: 0,
    })
  );
  const idOfValue = (v: string) => assets.find((x) => x.value === v)?.id;
  assets.forEach((a) => {
    const pid = a.parent ? idOfValue(a.parent) : undefined;
    edges.push({ a: pid ?? ORG, b: a.id });
  });
  return { nodes, edges };
}

/** Fruchterman–Reingold force layout (deterministic seed), normalized to the stage. */
function layout(nodes: GNode[], edges: GEdge[]): Record<string, GNode> {
  const N = nodes.length || 1;
  const pos = nodes.map((n, i) => ({
    ...n,
    x: Math.cos((2 * Math.PI * i) / N) * 170 + (i % 2 ? 24 : -24),
    y: Math.sin((2 * Math.PI * i) / N) * 130,
  }));
  const idx = new Map(pos.map((n, i) => [n.id, i]));
  const k = Math.sqrt((STAGE_W * STAGE_H) / N) * 0.62;
  const iters = 380;
  for (let it = 0; it < iters; it++) {
    const disp = pos.map(() => ({ x: 0, y: 0 }));
    for (let i = 0; i < pos.length; i++)
      for (let j = i + 1; j < pos.length; j++) {
        let dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y;
        const d = Math.hypot(dx, dy) || 0.01;
        const f = (k * k) / d; dx /= d; dy /= d;
        disp[i].x += dx * f; disp[i].y += dy * f; disp[j].x -= dx * f; disp[j].y -= dy * f;
      }
    for (const e of edges) {
      const i = idx.get(e.a), j = idx.get(e.b);
      if (i === undefined || j === undefined) continue;
      let dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y;
      const d = Math.hypot(dx, dy) || 0.01;
      const f = (d * d) / k; dx /= d; dy /= d;
      disp[i].x -= dx * f; disp[i].y -= dy * f; disp[j].x += dx * f; disp[j].y += dy * f;
    }
    for (let i = 0; i < pos.length; i++) { disp[i].x += -pos[i].x * 0.015; disp[i].y += -pos[i].y * 0.015; }
    const t = Math.max(2, 42 * (1 - it / iters));
    for (let i = 0; i < pos.length; i++) {
      const dl = Math.hypot(disp[i].x, disp[i].y) || 0.01;
      pos[i].x += (disp[i].x / dl) * Math.min(dl, t);
      pos[i].y += (disp[i].y / dl) * Math.min(dl, t);
    }
  }
  const xs = pos.map((p) => p.x), ys = pos.map((p) => p.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
  const pad = 72, w = Math.max(1, maxX - minX), h = Math.max(1, maxY - minY);
  const s = Math.min((STAGE_W - pad * 2) / w, (STAGE_H - pad * 2) / h);
  const out: Record<string, GNode> = {};
  pos.forEach((p) => { out[p.id] = { ...p, x: pad + (p.x - minX) * s, y: pad + (p.y - minY) * s }; });
  return out;
}
