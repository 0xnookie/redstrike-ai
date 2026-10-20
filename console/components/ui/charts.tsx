"use client";

import { cx } from "@/lib/format";

/* ---------- Donut (SVG, theme-aware track) ---------- */
export function Donut({
  data, size = 150, thickness = 18, centerLabel, centerSub,
}: {
  data: { label: string; value: number; color: string }[];
  size?: number; thickness?: number; centerLabel?: React.ReactNode; centerSub?: string;
}) {
  const total = data.reduce((a, d) => a + d.value, 0);
  const r = (size - thickness) / 2;
  const C = 2 * Math.PI * r;
  const cx0 = size / 2;
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0">
      <circle cx={cx0} cy={cx0} r={r} fill="none" strokeWidth={thickness} className="stroke-line" />
      {total > 0 &&
        data.filter((d) => d.value > 0).map((d, i) => {
          const len = (d.value / total) * C;
          const seg = (
            <circle
              key={i} cx={cx0} cy={cx0} r={r} fill="none" stroke={d.color} strokeWidth={thickness}
              strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset}
              transform={`rotate(-90 ${cx0} ${cx0})`} strokeLinecap="butt"
            />
          );
          offset += len;
          return seg;
        })}
      <text x={cx0} y={cx0 - 2} textAnchor="middle" className="fill-fg" fontSize={size * 0.19} fontWeight={700}>
        {centerLabel ?? total}
      </text>
      {centerSub && (
        <text x={cx0} y={cx0 + size * 0.13} textAnchor="middle" className="fill-muted" fontSize={size * 0.075}>
          {centerSub}
        </text>
      )}
    </svg>
  );
}

export function Legend({ data }: { data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((a, d) => a + d.value, 0);
  return (
    <div className="flex-1 space-y-1.5">
      {data.map((d) => (
        <div key={d.label} className="flex items-center justify-between gap-3 text-xs">
          <span className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: d.color }} />
            {d.label}
          </span>
          <span className="tabular-nums text-muted">
            {d.value}
            {total ? ` · ${Math.round((d.value / total) * 100)}%` : ""}
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

/* ---------- Thin progress bar ---------- */
export function Progress({ value, max = 100, color = "#22c55e", className }: { value: number; max?: number; color?: string; className?: string }) {
  return (
    <div className={cx("h-1.5 w-full overflow-hidden rounded-full bg-line", className)}>
      <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(100, (value / max) * 100)}%`, background: color }} />
    </div>
  );
}
