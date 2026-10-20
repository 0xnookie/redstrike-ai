"use client";

import { useMemo } from "react";
import { Card } from "@/components/ui/primitives";
import type { TestRun, ActivityEvent } from "@/lib/types";

const DAY = 86_400_000;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
// Blue intensity ramp (empty → More). This encodes DATA (activity volume), so it
// keeps color — consistent with the console's monochrome-chrome / colored-data split.
const RAMP = ["rgb(var(--fg) / 0.05)", "#0e3a57", "#15618f", "#1f8fd0", "#58c4f5"];
const PITCH = 15; // 12px cell + 3px gap

function isoDay(t: number) {
  return new Date(t).toISOString().slice(0, 10);
}
// Monday of the week containing `d` (UTC).
function mondayOf(d: Date) {
  const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dow = (x.getUTCDay() + 6) % 7; // Mon=0 … Sun=6
  x.setUTCDate(x.getUTCDate() - dow);
  return x;
}

/**
 * GitHub-style contribution heatmap of testing activity — test runs (by
 * startedAt) + agent actions (activity events, by ts) counted per day, laid out
 * Jan → today of the most recent year in the data. Empty data → a faint grid.
 */
export function TestingActivity({ tests, activity }: { tests: TestRun[]; activity: ActivityEvent[] }) {
  const { weeks, monthLabels, max, total, activeDays, busiest } = useMemo(() => {
    const counts = new Map<string, number>();
    const bump = (iso?: string) => {
      if (!iso) return;
      const k = iso.slice(0, 10);
      counts.set(k, (counts.get(k) || 0) + 1);
    };
    tests.forEach((t) => bump(t.startedAt));
    activity.forEach((a) => bump(a.ts));

    const stamps = [
      ...tests.map((t) => +new Date(t.startedAt)),
      ...activity.map((a) => +new Date(a.ts)),
    ].filter((n) => !isNaN(n));
    const endMs = stamps.length ? Math.max(...stamps) : Date.now();
    const end = new Date(endMs);
    const yearStartMs = +new Date(Date.UTC(end.getUTCFullYear(), 0, 1));
    const gridStart = +mondayOf(new Date(yearStartMs));
    const gridEnd = +mondayOf(end);

    const weeks: { day: string; count: number; inRange: boolean }[][] = [];
    const monthLabels: { col: number; label: string }[] = [];
    let col = 0;
    let lastMonth = -1;
    for (let w = gridStart; w <= gridEnd; w += 7 * DAY, col++) {
      const week: { day: string; count: number; inRange: boolean }[] = [];
      for (let d = 0; d < 7; d++) {
        const t = w + d * DAY;
        const inRange = t >= yearStartMs && t <= endMs;
        const k = isoDay(t);
        week.push({ day: k, count: inRange ? counts.get(k) || 0 : 0, inRange });
      }
      const m = new Date(w).getUTCMonth();
      if (m !== lastMonth) {
        // skip the leading partial week that belongs to the prior December, so the
        // first label is January (avoids a cramped "Dec Jan" overlap)
        if (w >= yearStartMs) monthLabels.push({ col, label: MONTHS[m] });
        lastMonth = m;
      }
      weeks.push(week);
    }
    const vals = [...counts.values()];
    return {
      weeks,
      monthLabels,
      max: Math.max(1, ...vals),
      total: vals.reduce((a, b) => a + b, 0),
      activeDays: counts.size,
      busiest: vals.length ? Math.max(...vals) : 0,
    };
  }, [tests, activity]);

  const level = (c: number) => (c <= 0 ? 0 : Math.min(4, 1 + Math.floor((c / max) * 3.999)));

  return (
    <Card className="flex h-full flex-col p-4">
      <div className="mb-3">
        <h2 className="text-sm font-semibold">Testing Activity</h2>
        <p className="text-xs text-muted">Tests + agent actions, by day</p>
      </div>

      <div className="my-auto overflow-x-auto scroll-thin">
        <div className="inline-block">
          {/* month labels */}
          <div className="relative mb-1 ml-8 h-4 text-[10px] text-muted" style={{ width: weeks.length * PITCH }}>
            {monthLabels.map((m) => (
              <span key={`${m.col}-${m.label}`} className="absolute top-0" style={{ left: m.col * PITCH }}>
                {m.label}
              </span>
            ))}
          </div>
          <div className="flex gap-[3px]">
            {/* weekday labels */}
            <div className="mr-1 flex w-7 flex-col gap-[3px] text-[10px] leading-[12px] text-muted">
              {["Mon", "", "Wed", "", "Fri", "", ""].map((d, i) => (
                <span key={i} className="h-[12px]">{d}</span>
              ))}
            </div>
            {/* week columns */}
            {weeks.map((week, wi) => (
              <div key={wi} className="flex flex-col gap-[3px]">
                {week.map((cell, di) => {
                  const lv = level(cell.count);
                  return (
                    <div
                      key={di}
                      className="h-[12px] w-[12px] rounded-[2px]"
                      style={{
                        background: cell.inRange ? RAMP[lv] : "transparent",
                        boxShadow: cell.inRange && lv === 0 ? "inset 0 0 0 1px rgb(var(--fg) / 0.04)" : undefined,
                      }}
                      title={cell.inRange ? `${cell.day} · ${cell.count} run${cell.count === 1 ? "" : "s"}` : undefined}
                    />
                  );
                })}
              </div>
            ))}
          </div>

          {/* legend */}
          <div className="mt-3 flex items-center gap-1.5 text-[10px] text-muted">
            <span>Less</span>
            {RAMP.map((c, i) => (
              <span key={i} className="h-[11px] w-[11px] rounded-[2px]" style={{ background: c }} />
            ))}
            <span>More</span>
          </div>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-3 gap-2 border-t border-line pt-3">
        <Stat label="Runs" value={total} />
        <Stat label="Active days" value={activeDays} />
        <Stat label="Busiest day" value={busiest} />
      </div>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-lg font-semibold leading-none tabular-nums">{value.toLocaleString("en-US")}</div>
      <div className="mt-1 text-[11px] text-muted">{label}</div>
    </div>
  );
}
