"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as RPointerEvent } from "react";
import { Search, Plus, Minus, Maximize2, X, Crosshair, ExternalLink, GitBranch } from "lucide-react";
import {
  buildEngagementGraph,
  type EngagementGraphInput, type EngagementGraphOptions, type GNode, type GNodeKind,
} from "@/lib/engagementGraph";
import { SEVERITY, sevMeta } from "@/lib/theme";
import { cx } from "@/lib/format";
import { EmptyState } from "@/components/ui/primitives";

/* kind → hue (data color; the chrome stays monochrome) + node width */
const KIND: Record<GNodeKind, { color: string; label: string; w: number }> = {
  scope: { color: "#94a3b8", label: "Scope", w: 152 },
  host: { color: "#38bdf8", label: "Host", w: 158 },
  service: { color: "#22d3ee", label: "Service", w: 120 },
  route: { color: "#a78bfa", label: "Endpoint", w: 188 },
  finding: { color: "#fb7185", label: "Finding", w: 198 },
  chain: { color: "#fb923c", label: "Chain", w: 174 },
  agent: { color: "#34d399", label: "Agent", w: 150 },
  // reasoning-provenance band (shown behind the "Reasoning" toggle / a lineage slice)
  fact: { color: "#c084fc", label: "Evidence", w: 210 },
  intent: { color: "#f472b6", label: "Hypothesis", w: 200 },
  goal: { color: "#fbbf24", label: "Goal", w: 172 },
};
const COL_X = [0, 212, 436, 696, 952, 1200, 1452, 1704];
const ROW_H = 40;
const NODE_H = 28;
const PAD = 48;
/** provenance node kinds — their legend chips appear only when the overlay is on. */
const PROV_KINDS: GNodeKind[] = ["fact", "intent", "goal"];

const EDGE_TINT: Record<string, string> = { chain: "#fb923c", agent: "#34d399", provenance: "#c084fc" };

/* severity rank → color, precomputed once (vs. an Object.values(SEVERITY).find per node per render) */
const RANK_COLOR: Record<number, string> = Object.fromEntries(Object.values(SEVERITY).map((s) => [s.rank, s.color]));

interface View { x: number; y: number; k: number }

export interface EngagementGraphProps {
  input: EngagementGraphInput;
  onOpenFinding?: (id: string) => void;
  onOpenHost?: (host: string) => void;
}

export function EngagementGraph({ input, onOpenFinding, onOpenHost }: EngagementGraphProps) {
  // default to the full surface when there are no findings yet (recon-only engagement),
  // otherwise keep the graph focused on endpoints that actually carry a finding.
  const [allRoutes, setAllRoutes] = useState(() => input.findings.filter((f) => !f.composite).length === 0);
  const [showServices, setShowServices] = useState(false);
  const [showAgents, setShowAgents] = useState(false);
  const [showProvenance, setShowProvenance] = useState(false);
  const [lineageFinding, setLineageFinding] = useState<string | null>(null);
  const [sevMin, setSevMin] = useState(0);
  const [focusHost, setFocusHost] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [selId, setSelId] = useState<string | null>(null);

  // the trace only matters if it actually carries provenance nodes — gate the controls on it so the
  // "Reasoning" affordances don't appear for an engagement with no trace.
  const hasTrace = !!input.trace && Array.isArray(input.trace.nodes) && input.trace.nodes.length > 0;

  const opts: EngagementGraphOptions = useMemo(
    () => ({ allRoutes, showServices, showAgents, sevMin, focusHost, showProvenance, lineageFinding }),
    [allRoutes, showServices, showAgents, sevMin, focusHost, showProvenance, lineageFinding],
  );
  const graph = useMemo(() => buildEngagementGraph(input, opts), [input, opts]);

  // Drop a stale "Why this finding" slice if the active engagement no longer has that finding
  // (e.g. the user switched engagements while a lineage slice was open).
  useEffect(() => {
    if (lineageFinding && !input.findings.some((f) => f.id === lineageFinding)) setLineageFinding(null);
  }, [input.findings, lineageFinding]);

  const pos = useMemo(() => {
    const m = new Map<string, { x: number; y: number; w: number }>();
    for (const n of graph.nodes) m.set(n.id, { x: COL_X[n.col] ?? 0, y: n.row * ROW_H, w: KIND[n.kind].w });
    return m;
  }, [graph]);

  const bounds = useMemo(() => {
    let minY = Infinity, maxY = -Infinity, maxX = 0;
    for (const p of pos.values()) { minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y); maxX = Math.max(maxX, p.x + p.w); }
    if (!isFinite(minY)) { minY = 0; maxY = 0; }
    return { minX: 0, minY: minY - NODE_H, maxX, maxY: maxY + NODE_H };
  }, [pos]);

  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  const sel = selId ? nodeById.get(selId) ?? null : null;

  // neighbors of the selection (for accenting)
  const neighbors = useMemo(() => {
    const s = new Set<string>();
    if (!selId) return s;
    for (const e of graph.edges) { if (e.source === selId) s.add(e.target); if (e.target === selId) s.add(e.source); }
    return s;
  }, [graph, selId]);

  // query dimming
  const q = query.trim().toLowerCase();
  const matched = useMemo(() => {
    if (!q) return null;
    const s = new Set<string>();
    for (const n of graph.nodes) if ((n.label + " " + (n.sub ?? "") + " " + (n.host ?? "")).toLowerCase().includes(q)) s.add(n.id);
    return s;
  }, [graph, q]);

  /* ---- pan / zoom ---- */
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 900, h: 560 });
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });
  const interacted = useRef(false);
  const fitSig = useRef("");

  // The canvas <div> is only in the tree once the graph has nodes (it's below the early return).
  // Effects that bind to wrapRef must therefore re-run when this flips true, or they'd bind to a
  // null ref on an empty-first mount (store still loading) and never attach to the real element.
  const hasCanvas = graph.nodes.length > 0;

  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const r = entries[0].contentRect;
      setSize({ w: Math.max(320, r.width), h: Math.max(360, r.height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [hasCanvas]);

  const fit = useCallback(() => {
    const cw = bounds.maxX - bounds.minX, ch = bounds.maxY - bounds.minY;
    if (cw <= 0 || ch <= 0) { setView({ x: PAD, y: PAD, k: 1 }); return; }
    const k = Math.max(0.18, Math.min(1.4, Math.min((size.w - PAD * 2) / cw, (size.h - PAD * 2) / ch)));
    setView({ x: (size.w - cw * k) / 2 - bounds.minX * k, y: (size.h - ch * k) / 2 - bounds.minY * k, k });
    interacted.current = false;
  }, [bounds, size]);

  // auto-fit when the visible graph changes shape (unless the user has panned/zoomed since)
  useEffect(() => {
    const sig = `${graph.nodes.length}:${graph.stats.rows}:${size.w}x${size.h}`;
    if (sig !== fitSig.current && !interacted.current) { fitSig.current = sig; fit(); }
    else fitSig.current = sig;
  }, [graph, size, fit]);

  // Zoom-to-cursor on wheel. React's synthetic onWheel is registered as a PASSIVE listener, so
  // e.preventDefault() there is a silent no-op (the page scrolls instead of zooming, with a console
  // warning). Attach our own { passive: false } native listener so the preventDefault actually takes.
  // Gated on hasCanvas (above) so it attaches once the graph populates, not just on first mount.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const px = e.clientX - rect.left, py = e.clientY - rect.top;
      setView((v) => {
        const k = Math.max(0.12, Math.min(2.4, v.k * Math.exp(-e.deltaY * 0.0012)));
        const cx = (px - v.x) / v.k, cy = (py - v.y) / v.k;
        interacted.current = true;
        return { k, x: px - cx * k, y: py - cy * k };
      });
    };
    el.addEventListener("wheel", handler, { passive: false });
    return () => el.removeEventListener("wheel", handler);
  }, [hasCanvas]);

  // Escape clears the current selection (and so closes the inspector).
  useEffect(() => {
    if (!selId) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setSelId(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [selId]);

  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);
  const onBgPointerDown = (e: RPointerEvent) => {
    (e.target as Element).setPointerCapture?.(e.pointerId);
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
  };
  const onPointerMove = (e: RPointerEvent) => {
    const d = drag.current; if (!d) return;
    const dx = e.clientX - d.x, dy = e.clientY - d.y;
    if (!d.moved && Math.hypot(dx, dy) < 4) return;
    d.moved = true; interacted.current = true;
    setView((v) => ({ ...v, x: d.vx + dx, y: d.vy + dy }));
  };
  const onPointerUp = () => { drag.current = null; };

  const zoomBy = (f: number) => setView((v) => {
    const k = Math.max(0.12, Math.min(2.4, v.k * f));
    const cx = size.w / 2, cy = size.h / 2;
    interacted.current = true;
    return { k, x: cx - ((cx - v.x) / v.k) * k, y: cy - ((cy - v.y) / v.k) * k };
  });

  // Edges + nodes are memoized OFF the `view` transform so a pan/zoom tick only updates the
  // wrapping <g transform> attribute — the (potentially large) node/edge subtree is not rebuilt
  // on every drag frame. Recomputes only when the graph shape, selection, search or layout change.
  const content = useMemo(() => {
    const dim = (id: string) => !!matched && !matched.has(id) && id !== selId && !neighbors.has(id);
    return (
      <>
        {/* edges */}
        {graph.edges.map((e) => {
          const a = pos.get(e.source), b = pos.get(e.target);
          if (!a || !b) return null;
          const sx = a.x + a.w, sy = a.y, tx = b.x, ty = b.y, mx = (sx + tx) / 2;
          const accent = selId === e.source || selId === e.target;
          const dimmed = dim(e.source) || dim(e.target);
          const tint = EDGE_TINT[e.rel];
          return (
            <path
              key={e.id}
              d={`M${sx.toFixed(1)},${sy.toFixed(1)} C${mx.toFixed(1)},${sy.toFixed(1)} ${mx.toFixed(1)},${ty.toFixed(1)} ${tx.toFixed(1)},${ty.toFixed(1)}`}
              fill="none"
              stroke={accent ? (tint ?? "rgb(var(--fg) / 0.55)") : tint ? tint : "rgb(var(--fg) / 0.16)"}
              strokeWidth={accent ? 1.8 : 1.1}
              opacity={dimmed ? 0.06 : accent ? 0.9 : tint ? 0.4 : 0.5}
            />
          );
        })}
        {/* nodes */}
        {graph.nodes.map((n) => {
          const p = pos.get(n.id)!;
          return (
            <NodeBox
              key={n.id}
              n={n} x={p.x} y={p.y} w={p.w}
              selected={n.id === selId}
              neighbor={neighbors.has(n.id)}
              dim={dim(n.id)}
              onClick={() => setSelId((cur) => (cur === n.id ? null : n.id))}
            />
          );
        })}
      </>
    );
  }, [graph, pos, selId, neighbors, matched]);

  if (!graph.nodes.length) {
    return (
      <div className="px-2 pb-6">
        <EmptyState
          title="No engagement surface to graph yet"
          hint="Once recon discovers hosts/endpoints and the vuln agents file findings, they connect here as one explorable graph. Load or run an engagement to populate it."
        />
      </div>
    );
  }

  const transform = `translate(${view.x.toFixed(2)} ${view.y.toFixed(2)}) scale(${view.k.toFixed(3)})`;

  return (
    <div className="relative">
      {/* controls */}
      <div className="flex flex-wrap items-center gap-2 px-4 pb-3 pt-1">
        <div className="relative">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search nodes…" aria-label="Search graph nodes"
            className="h-8 w-44 rounded-full border border-line bg-card2 pl-8 pr-3 text-xs text-fg outline-none transition focus:border-fg/40"
          />
        </div>
        <SevSelect value={sevMin} onChange={setSevMin} />
        <Toggle label="All endpoints" on={allRoutes} onClick={() => setAllRoutes((v) => !v)} />
        <Toggle label="Services" on={showServices} onClick={() => setShowServices((v) => !v)} />
        <Toggle label="Agents" on={showAgents} onClick={() => setShowAgents((v) => !v)} />
        {hasTrace && (
          <Toggle label="Reasoning" on={showProvenance || !!lineageFinding}
            onClick={() => { if (lineageFinding) setLineageFinding(null); else setShowProvenance((v) => !v); }} />
        )}
        {focusHost && (
          <button onClick={() => setFocusHost(null)} className="btn-ghost !h-8" title="Clear host focus">
            <Crosshair size={13} /> {focusHost} <X size={12} />
          </button>
        )}
        {lineageFinding && (
          <button onClick={() => setLineageFinding(null)} className="btn-ghost !h-8" title="Clear lineage slice">
            <GitBranch size={13} /> Why {lineageFinding} <X size={12} />
          </button>
        )}
        <div className="ml-auto flex items-center gap-1.5">
          <button onClick={() => zoomBy(1 / 1.2)} className="icon-btn" title="Zoom out" aria-label="Zoom out"><Minus size={14} /></button>
          <button onClick={() => zoomBy(1.2)} className="icon-btn" title="Zoom in" aria-label="Zoom in"><Plus size={14} /></button>
          <button onClick={fit} className="btn-ghost !h-8" title="Fit to view"><Maximize2 size={13} /> Fit</button>
        </div>
      </div>

      {/* canvas */}
      <div
        ref={wrapRef}
        className="graph-grid relative overflow-hidden border-y border-line/60"
        style={{ height: "clamp(480px, 66vh, 760px)", cursor: drag.current ? "grabbing" : "grab", touchAction: "none" }}
        onPointerDown={onBgPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
      >
        <svg width="100%" height="100%" role="img" aria-label="Engagement exploration graph">
          <g transform={transform}>{content}</g>
        </svg>

        {/* inspector */}
        {sel && (
          <Inspector
            node={sel}
            onClose={() => setSelId(null)}
            onFocusHost={sel.host ? () => { setFocusHost(sel.host!); } : undefined}
            onOpenFinding={sel.findingId && onOpenFinding ? () => onOpenFinding(sel.findingId!) : undefined}
            onOpenHost={sel.hostName && onOpenHost ? () => onOpenHost(sel.hostName!) : undefined}
            onWhy={hasTrace && sel.kind === "finding" && sel.findingId
              ? () => { setLineageFinding(sel.findingId!); setSelId(null); } : undefined}
          />
        )}
      </div>

      {/* legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 px-5 py-3 text-[12px] text-muted">
        {([
          "scope", "host", "service", "route", "finding", "chain", "agent",
          ...((showProvenance || lineageFinding) ? PROV_KINDS : []),
        ] as GNodeKind[]).map((k) => (
          <span key={k} className="inline-flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-[3px]" style={{ background: KIND[k].color }} /> {KIND[k].label}
          </span>
        ))}
        <span className="ml-auto font-mono text-[11px] text-faint">
          {lineageFinding
            ? `lineage of ${lineageFinding} · ${graph.stats.fact + graph.stats.intent + graph.stats.goal} reasoning steps`
            : `${graph.stats.host} hosts · ${graph.stats.route} endpoints · ${graph.stats.finding} findings · ${graph.stats.chain} chains${(showProvenance && (graph.stats.fact || graph.stats.intent)) ? ` · ${graph.stats.fact + graph.stats.intent + graph.stats.goal} reasoning` : ""}`}
        </span>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- node ---- */
function NodeBox({ n, x, y, w, selected, neighbor, dim, onClick }: {
  n: GNode; x: number; y: number; w: number; selected: boolean; neighbor: boolean; dim: boolean; onClick: () => void;
}) {
  const [focused, setFocused] = useState(false);
  const color = n.kind === "finding" && n.severity ? sevMeta(n.severity).color : KIND[n.kind].color;
  const sevColor = n.sevRank > 0 ? RANK_COLOR[n.sevRank] : undefined;
  const stroke = selected ? "rgb(var(--fg-strong))"
    : focused ? "rgb(var(--fg) / 0.7)"
    : neighbor ? "rgb(var(--fg) / 0.45)"
    : sevColor ? sevColor + "88" : "rgb(var(--line))";
  const label = `${KIND[n.kind].label}: ${n.label}${n.sub ? " — " + n.sub : ""}`;
  return (
    <g
      transform={`translate(${x},${(y - NODE_H / 2).toFixed(1)})`}
      role="button"
      tabIndex={0}
      aria-label={label}
      aria-pressed={selected}
      style={{ cursor: "pointer", opacity: dim ? 0.22 : 1, outline: "none" }}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); onClick(); } }}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onPointerDown={(e) => e.stopPropagation()}
    >
      <title>{label}</title>
      <rect
        width={w} height={NODE_H} rx={7}
        style={{ fill: "rgb(var(--card))", stroke, strokeWidth: selected || focused ? 2 : 1.1 }}
      />
      {/* kind accent bar */}
      <rect x={0} y={0} width={3.5} height={NODE_H} rx={2} style={{ fill: color }} />
      {/* finding severity dot */}
      {n.kind === "finding" && n.severity && (
        <circle cx={w - 10} cy={NODE_H / 2} r={3.5} style={{ fill: sevMeta(n.severity).color }} />
      )}
      <text x={11} y={12.5} style={{ font: "600 11px var(--font-mono)", fill: "rgb(var(--fg-strong))" }}>
        {clip(n.label, n.kind === "route" || n.kind === "host" ? 22 : 18)}
      </text>
      {n.sub && (
        <text x={11} y={23} style={{ font: "10px var(--font-sans)", fill: "rgb(var(--faint))" }}>
          {clip(n.sub, n.kind === "finding" ? 24 : 22)}
        </text>
      )}
    </g>
  );
}
const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

/* ------------------------------------------------------------- inspector --- */
function Inspector({ node, onClose, onFocusHost, onOpenFinding, onOpenHost, onWhy }: {
  node: GNode; onClose: () => void;
  onFocusHost?: () => void; onOpenFinding?: () => void; onOpenHost?: () => void; onWhy?: () => void;
}) {
  const rows = Object.entries(node.meta ?? {}).filter(([, v]) => v != null && v !== "");
  return (
    <div
      role="dialog"
      aria-label={`${KIND[node.kind].label} details: ${node.label}`}
      className="absolute right-3 top-3 z-10 w-[300px] max-w-[calc(100%-24px)] rounded-xl border border-line bg-card/95 p-4 shadow-pop backdrop-blur"
    >
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wide text-faint">
            <span className="h-2 w-2 rounded-[3px]" style={{ background: node.kind === "finding" && node.severity ? sevMeta(node.severity).color : KIND[node.kind].color }} />
            {KIND[node.kind].label}
          </div>
          <div className="mt-1 break-words font-mono text-sm text-fg-strong">{node.label}</div>
          {node.sub && <div className="mt-0.5 break-words text-xs text-muted">{node.sub}</div>}
        </div>
        <button onClick={onClose} className="icon-btn shrink-0" aria-label="Close"><X size={14} /></button>
      </div>
      {rows.length > 0 && (
        <dl className="mt-3 space-y-1.5 border-t border-line/70 pt-3 text-xs">
          {rows.map(([k, v]) => (
            <div key={k} className="flex items-start justify-between gap-3">
              <dt className="shrink-0 capitalize text-faint">{k}</dt>
              <dd className="min-w-0 break-words text-right font-mono text-fg">{String(v)}</dd>
            </div>
          ))}
        </dl>
      )}
      <div className="mt-3 flex flex-wrap gap-1.5">
        {onWhy && <button onClick={onWhy} className="btn-ghost !h-8" title="Show this finding's reasoning lineage"><GitBranch size={13} /> Why this finding</button>}
        {onOpenFinding && <button onClick={onOpenFinding} className="btn-ghost !h-8"><ExternalLink size={13} /> Open finding</button>}
        {onOpenHost && <button onClick={onOpenHost} className="btn-ghost !h-8"><ExternalLink size={13} /> Open host</button>}
        {onFocusHost && node.kind === "host" && <button onClick={onFocusHost} className="btn-ghost !h-8"><Crosshair size={13} /> Focus subtree</button>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- controls ---- */
function Toggle({ label, on, onClick }: { label: string; on: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={on}
      className={cx(
        "h-8 rounded-full border px-3 text-xs font-medium transition",
        on ? "border-fg/40 bg-fg/[0.06] text-fg" : "border-line bg-card2 text-muted hover:text-fg",
      )}
    >
      {label}
    </button>
  );
}

function SevSelect({ value, onChange }: { value: number; onChange: (n: number) => void }) {
  const OPTS = [{ v: 0, l: "All severities" }, { v: 2, l: "Low+" }, { v: 3, l: "Medium+" }, { v: 4, l: "High+" }, { v: 5, l: "Critical" }];
  return (
    <div className="relative inline-flex">
      <select
        value={value} onChange={(e) => onChange(Number(e.target.value))}
        className="h-8 cursor-pointer appearance-none rounded-full border border-line bg-card2 pl-3 pr-7 text-xs text-fg outline-none transition focus:border-fg/40"
      >
        {OPTS.map((o) => <option key={o.v} value={o.v}>{o.l}</option>)}
      </select>
      <svg width="12" height="12" viewBox="0 0 24 24" className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-muted"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" strokeWidth="2" /></svg>
    </div>
  );
}
