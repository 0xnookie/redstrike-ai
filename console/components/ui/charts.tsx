"use client";

import { useRef, useState } from "react";
import { cx } from "@/lib/format";

type Series = { label: string; value: number; color: string };
const pct = (v: number, total: number) => (total ? Math.round((v / total) * 100) : 0);

/** Hover state for a series chart. Controlled when `active`/`onActive` are passed (so a
 *  Donut and its Legend can share one highlight), otherwise self-contained. */
function useActive(active?: string | null, onActive?: (label: string | null) => void) {
  const [own, setOwn] = useState<string | null>(null);
  return onActive ? ([active ?? null, onActive] as const) : ([own, setOwn] as const);
}

/* ---------- Donut (SVG, theme-aware track; hover dims the other segments) ---------- */
export function Donut({
  data, size = 150, thickness = 18, centerLabel, centerSub, active, onActive,
}: {
  data: Series[];
  size?: number; thickness?: number; centerLabel?: React.ReactNode; centerSub?: string;
  active?: string | null; onActive?: (label: string | null) => void;
}) {
  const [hot, setHot] = useActive(active, onActive);
  const total = data.reduce((a, d) => a + d.value, 0);
  const r = (size - thickness) / 2;
  const C = 2 * Math.PI * r;
  const cx0 = size / 2;
  const segs = data.filter((d) => d.value > 0);
  const GAP = segs.length > 1 ? thickness * 1.3 : 0;
  const hit = hot ? segs.find((d) => d.label === hot) : undefined;
  let offset = 0;
  return (
    <svg
      width={size} height={size} viewBox={`0 0 ${size} ${size}`} className={cx("shrink-0", hit && "donut-dim")}
      onPointerLeave={() => setHot(null)}
    >
      <circle cx={cx0} cy={cx0} r={r} fill="none" strokeWidth={thickness} className="stroke-line" />
      {total > 0 &&
        segs.map((d) => {
          const frac = (d.value / total) * C;
          const len = Math.max(1, frac - GAP);
          const seg = (
            <circle
              key={d.label} cx={cx0} cy={cx0} r={r} fill="none" stroke={d.color} strokeWidth={thickness}
              strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset}
              transform={`rotate(-90 ${cx0} ${cx0})`} strokeLinecap="round"
              className={cx("donut-seg", hit?.label === d.label && "on")}
              onPointerEnter={() => setHot(d.label)}
            >
              <title>{`${d.label}: ${d.value} (${pct(d.value, total)}%)`}</title>
            </circle>
          );
          offset += frac;
          return seg;
        })}
      {/* center: the total — or, while a segment is hovered, that segment's count + share */}
      <text x={cx0} y={cx0 - 2} textAnchor="middle" className="fill-fg" fontSize={size * 0.19} fontWeight={700}>
        {hit ? hit.value : centerLabel ?? total}
      </text>
      {(hit || centerSub) && (
        <text x={cx0} y={cx0 + size * 0.13} textAnchor="middle" className="fill-muted" fontSize={size * 0.075}>
          {hit ? `${hit.label} · ${pct(hit.value, total)}%` : centerSub}
        </text>
      )}
    </svg>
  );
}

export function Legend({
  data, active, onActive,
}: { data: Series[]; active?: string | null; onActive?: (label: string | null) => void }) {
  const [hot, setHot] = useActive(active, onActive);
  const total = data.reduce((a, d) => a + d.value, 0);
  const lit = hot && data.some((d) => d.label === hot && d.value > 0);
  return (
    <div className={cx("flex-1 space-y-1.5", lit && "legend-dim")} onPointerLeave={() => setHot(null)}>
      {data.map((d) => (
        <div
          key={d.label}
          className={cx("legend-row flex items-center justify-between gap-3 text-xs", hot === d.label && "on")}
          onPointerEnter={() => setHot(d.value > 0 ? d.label : null)}
        >
          <span className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: d.color }} />
            {d.label}
          </span>
          <span className="shrink-0 whitespace-nowrap tabular-nums text-muted">
            {d.value}
            {total ? ` · ${pct(d.value, total)}%` : ""}
          </span>
        </div>
      ))}
    </div>
  );
}

/* ---------- Horizontal bars ---------- */
export function HBars({
  data, accent = "rgb(var(--fg) / 0.82)", valueSuffix = "",
}: { data: { label: string; value: number; color?: string }[]; accent?: string; valueSuffix?: string }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  if (!data.length) return <p className="text-xs text-muted">No data</p>;
  return (
    <div className="space-y-2.5">
      {data.map((d) => (
        <div key={d.label} className="text-xs">
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="truncate" title={d.label}>{d.label}</span>
            <span className="tabular-nums text-muted">{d.value}{valueSuffix}</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-line">
            <div className="h-full rounded-full" style={{ width: `${(d.value / max) * 100}%`, background: d.color ?? accent }} />
          </div>
        </div>
      ))}
    </div>
  );
}

/* ---------- Vertical stacked bars (e.g. findings by day, by severity) ---------- */
export function StackedBars({
  groups, series, height = 180,
}: {
  groups: { label: string; values: Record<string, number> }[];
  series: { key: string; color: string; label: string }[];
  height?: number;
}) {
  const max = Math.max(1, ...groups.map((g) => series.reduce((a, s) => a + (g.values[s.key] || 0), 0)));
  return (
    <div>
      <div className="flex items-end gap-3" style={{ height }}>
        {groups.map((g) => {
          const total = series.reduce((a, s) => a + (g.values[s.key] || 0), 0);
          return (
            <div key={g.label} className="flex flex-1 flex-col items-center justify-end gap-1">
              <div className="flex w-full max-w-[42px] flex-col-reverse overflow-hidden rounded-md" style={{ height: `${(total / max) * (height - 24)}px` }}>
                {series.map((s) => {
                  const v = g.values[s.key] || 0;
                  if (!v) return null;
                  return <div key={s.key} style={{ height: `${(v / total) * 100}%`, background: s.color }} title={`${s.label}: ${v}`} />;
                })}
              </div>
              <span className="text-[10px] text-muted">{g.label}</span>
            </div>
          );
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-3">
        {series.map((s) => (
          <span key={s.key} className="flex items-center gap-1.5 text-[11px] text-muted">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ---------- Area / line chart (currentColor-driven, theme-aware) ----------
   Hover shows a crosshair, the nearest point and a tooltip. Those overlays are HTML
   positioned in % over the SVG: the SVG stretches horizontally (preserveAspectRatio
   "none"), which would squash any marker drawn inside it into an ellipse. */
export function AreaLine({
  points, labels, valueLabel = "Value", height = 190, className, fill = true,
}: {
  points: number[]; labels?: string[]; valueLabel?: string;
  height?: number; className?: string; fill?: boolean;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const W = 600, H = height, pad = 8;
  const n = points.length;
  if (n < 2) {
    return (
      <div className="flex items-center justify-center text-xs text-muted" style={{ height }}>
        Not enough dated data yet.
      </div>
    );
  }
  const max = Math.max(1, ...points);
  const min = Math.min(0, ...points);
  const span = max - min || 1;
  const x = (i: number) => pad + (i / (n - 1)) * (W - 2 * pad);
  const y = (v: number) => H - pad - ((v - min) / span) * (H - 2 * pad);
  const line = points.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(n - 1).toFixed(1)},${(H - pad).toFixed(1)}L${x(0).toFixed(1)},${(H - pad).toFixed(1)}Z`;
  const gid = `al-${n}-${Math.round(max)}`;

  // pointer x → nearest data index (inverse of x(), in the SVG's stretched coordinate space)
  const onMove = (e: React.PointerEvent) => {
    const r = wrap.current?.getBoundingClientRect();
    if (!r || !r.width) return;
    const vx = ((e.clientX - r.left) / r.width) * W;
    const i = Math.round(((vx - pad) / (W - 2 * pad)) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  };
  const at = hover ?? n - 1; // idle: mark the latest point, as before
  const leftPct = (x(at) / W) * 100;
  const topPct = (y(points[at]) / H) * 100;
  const prev = at > 0 ? points[at] - points[at - 1] : null;

  return (
    <div
      ref={wrap}
      className={cx("relative w-full text-fg", className)}
      style={{ height, cursor: "crosshair" }}
      onPointerMove={onMove}
      onPointerLeave={() => setHover(null)}
    >
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="block h-full w-full" aria-hidden>
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={W} y1={H * f} y2={H * f} className="stroke-line" strokeWidth={1} shapeRendering="crispEdges" vectorEffect="non-scaling-stroke" />
        ))}
        <defs>
          <linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity={0.22} />
            <stop offset="100%" stopColor="currentColor" stopOpacity={0} />
          </linearGradient>
        </defs>
        {fill && <path d={area} fill={`url(#${gid})`} />}
        <path d={line} fill="none" stroke="currentColor" strokeWidth={2} vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />
      </svg>
      {hover != null && <span className="chart-cross" style={{ left: `${leftPct}%` }} />}
      <span className="chart-point" style={{ left: `${leftPct}%`, top: `${topPct}%` }} />
      {hover != null && (
        <div
          className="chart-tip"
          style={{
            top: 4,
            // keep the tooltip inside the chart: flip to the left of the crosshair past the midpoint
            ...(leftPct > 55 ? { right: `calc(${100 - leftPct}% + 12px)` } : { left: `calc(${leftPct}% + 12px)` }),
          }}
        >
          <div className="chart-tip-h">{labels?.[at] ?? `point ${at + 1} of ${n}`}</div>
          <div className="chart-tip-r">
            <span>{valueLabel}</span>
            <b>{points[at]}</b>
          </div>
          {prev != null && prev !== 0 && (
            <div className="chart-tip-r">
              <span>change</span>
              <b>{prev > 0 ? `+${prev}` : prev}</b>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------- Thin progress bar ---------- */
export function Progress({ value, max = 100, color = "#22c55e", className, animated = false }: { value: number; max?: number; color?: string; className?: string; animated?: boolean }) {
  return (
    <div className={cx("h-1.5 w-full overflow-hidden rounded-full bg-line", className)}>
      <div className={cx("h-full rounded-full transition-all", animated && "progress-live")} style={{ width: `${Math.min(100, (value / max) * 100)}%`, background: color }} />
    </div>
  );
}
