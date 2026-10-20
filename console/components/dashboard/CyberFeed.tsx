"use client";

import { useMemo } from "react";
import { Card, Dot } from "@/components/ui/primitives";
import { fmtDate } from "@/lib/format";
import { SEVERITY } from "@/lib/theme";
import type { CveFeed, CveItem, Severity } from "@/lib/types";

/** Age of an item relative to the feed's generated_at (deterministic — no Date.now). */
function age(published: string, ref: string): string {
  const p = +new Date(published);
  const r = +new Date(ref);
  if (isNaN(p) || isNaN(r)) return "";
  const days = Math.floor((r - p) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "1d ago";
  if (days < 30) return `${days}d ago`;
  return new Date(published).toISOString().slice(0, 10);
}

function sevOf(it: CveItem): Severity | undefined {
  if (it.severity) return it.severity;
  if (typeof it.cvss === "number") {
    return it.cvss >= 9 ? "critical" : it.cvss >= 7 ? "high" : it.cvss >= 4 ? "medium" : it.cvss > 0 ? "low" : "info";
  }
  return undefined;
}

/**
 * "What's New in Cyber" — a global CVE feed (not engagement-scoped): the 7-/30-day
 * detection counts, a dotted globe, and the newest vulnerability detections. The
 * feed is data the console renders; it names no external source. A live deployment
 * can override the demo feed by serving `cve_feed.json` next to the console.
 */
export function CyberFeed({ feed, live = false }: { feed?: CveFeed; live?: boolean }) {
  if (!feed) return null;
  const items = feed.items ?? [];

  return (
    <Card className="overflow-hidden p-0">
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <h2 className="text-sm font-semibold">What&apos;s New in Cyber</h2>
        <div className="flex items-center gap-2 text-[11px] text-muted">
          {live ? (
            <span className="inline-flex items-center gap-1.5 font-medium text-fg"><Dot color="#22c55e" pulse /> Live</span>
          ) : (
            <span>Demo feed</span>
          )}
          <span className="text-muted/60">·</span>
          <span>Updated {fmtDate(feed.generated_at)}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2">
        {/* left: counts + globe */}
        <div className="relative min-h-[300px] overflow-hidden border-b border-line p-5 lg:border-b-0 lg:border-r">
          <h3 className="text-sm font-semibold">Newest vulnerability detections</h3>
          <div className="mt-4 flex gap-10">
            <div>
              <div className="text-4xl font-semibold tabular-nums">{feed.count_7d.toLocaleString("en-US")}</div>
              <div className="mt-1 text-xs text-muted">in last 7 days</div>
            </div>
            <div>
              <div className="text-4xl font-semibold tabular-nums">{feed.count_30d.toLocaleString("en-US")}</div>
              <div className="mt-1 text-xs text-muted">in last 30 days</div>
            </div>
          </div>
          <DotGlobe className="pointer-events-none absolute -bottom-20 left-1/2 -translate-x-1/2 opacity-95" />
        </div>

        {/* right: newest detections */}
        <div className="max-h-[384px] divide-y divide-line overflow-y-auto scroll-thin">
          {items.length === 0 ? (
            <p className="p-6 text-center text-xs text-muted">No recent detections.</p>
          ) : (
            items.map((it) => {
              const sv = sevOf(it);
              const m = sv ? SEVERITY[sv] : undefined;
              return (
                <div key={it.id} className="flex items-start gap-3 px-4 py-3">
                  <span className="mt-0.5 h-9 w-[3px] shrink-0 rounded-full" style={{ background: m?.color ?? "rgb(var(--fg) / 0.18)" }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-sm font-medium">{it.id}</span>
                      <span className="shrink-0 text-[11px] text-muted">{age(it.published, feed.generated_at)}</span>
                    </div>
                    <p className="mt-0.5 line-clamp-1 text-xs text-muted">{it.summary}</p>
                  </div>
                  <div className="shrink-0 pl-1 text-right">
                    {m && <div className="text-[11px] font-medium" style={{ color: m.color }}>{m.label}</div>}
                    {typeof it.cvss === "number" && <div className="text-[11px] tabular-nums text-muted">CVSS {it.cvss.toFixed(1)}</div>}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </Card>
  );
}

/* ---------- dotted globe (hand-rolled SVG, theme-aware, deterministic) ---------- */
function DotGlobe({ className }: { className?: string }) {
  const R = 174;
  const { dots, markers } = useMemo(() => {
    const N = 900;
    const tilt = -0.32; // rotate the sphere about X so the north pole leans back
    const ct = Math.cos(tilt), st = Math.sin(tilt);
    const golden = Math.PI * (3 - Math.sqrt(5));
    const dots: { x: number; y: number; o: number }[] = [];
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2; // 1 … -1
      const rad = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = golden * i;
      const x = Math.cos(theta) * rad;
      const z = Math.sin(theta) * rad;
      const yy = y * ct - z * st;
      const zz = y * st + z * ct;
      if (zz < -0.06) continue; // front hemisphere only
      dots.push({ x: R + x * R, y: R - yy * R, o: 0.16 + Math.max(0, zz) * 0.6 });
    }
    const mk = (lat: number, lon: number) => {
      const la = (lat * Math.PI) / 180;
      const lo = (lon * Math.PI) / 180;
      const x = Math.cos(la) * Math.cos(lo);
      const y = Math.sin(la);
      const z = Math.cos(la) * Math.sin(lo);
      const yy = y * ct - z * st;
      const zz = y * st + z * ct;
      return { x: R + x * R, y: R - yy * R, z: zz };
    };
    const markers = [mk(39, -98), mk(49, 11), mk(-14, -52), mk(35, 104), mk(1, 37), mk(-33, 151)].filter((m) => m.z > -0.02);
    return { dots, markers };
  }, []);

  return (
    <svg className={className} width={R * 2} height={R * 2} viewBox={`0 0 ${R * 2} ${R * 2}`} aria-hidden="true">
      {dots.map((d, i) => (
        <circle key={i} cx={d.x} cy={d.y} r={1.1} fill="rgb(var(--fg))" opacity={d.o * 0.62} />
      ))}
      {markers.map((m, i) => (
        <g key={i}>
          <circle cx={m.x} cy={m.y} r={5} fill="#f43f5e">
            <animate attributeName="r" values="4;11;4" dur="2.6s" begin={`${i * 0.4}s`} repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.4;0;0.4" dur="2.6s" begin={`${i * 0.4}s`} repeatCount="indefinite" />
          </circle>
          <circle cx={m.x} cy={m.y} r={2.4} fill="#f43f5e" />
        </g>
      ))}
    </svg>
  );
}
