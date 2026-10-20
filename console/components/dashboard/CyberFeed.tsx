"use client";

import { useEffect, useRef } from "react";
import { ExternalLink } from "lucide-react";
import { Card, Dot } from "@/components/ui/primitives";
import { fmtDate } from "@/lib/format";
import { cveRecordUrl } from "@/lib/cveFeed";
import { isLand } from "@/lib/landMask";
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
 * detection counts, a spinning dotted globe, and the newest vulnerability detections,
 * each linking out to its authoritative record. Fed live (lib/cveFeed.ts) or by a
 * served cve_feed.json; falls back to the bundled snapshot offline.
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
                <a
                  key={it.id}
                  href={cveRecordUrl(it.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`${it.id} — open full record`}
                  className="group flex items-start gap-3 px-4 py-3 transition hover:bg-card2"
                >
                  <span className="mt-0.5 h-9 w-[3px] shrink-0 rounded-full" style={{ background: m?.color ?? "rgb(var(--fg) / 0.18)" }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="inline-flex min-w-0 items-center gap-1.5">
                        <span className="font-mono text-sm font-medium group-hover:underline">{it.id}</span>
                        <ExternalLink size={11} className="shrink-0 text-muted opacity-0 transition group-hover:opacity-100" />
                      </span>
                      <span className="shrink-0 text-[11px] text-muted">{age(it.published, feed.generated_at)}</span>
                    </div>
                    <p className="mt-0.5 line-clamp-1 text-xs text-muted">{it.summary}</p>
                  </div>
                  <div className="shrink-0 pl-1 text-right">
                    {m && <div className="text-[11px] font-medium" style={{ color: m.color }}>{m.label}</div>}
                    {typeof it.cvss === "number" && <div className="text-[11px] tabular-nums text-muted">CVSS {it.cvss.toFixed(1)}</div>}
                  </div>
                </a>
              );
            })
          )}
        </div>
      </div>
    </Card>
  );
}

/* ---------- spinning Earth globe (canvas, theme-aware) ---------- */
// The dots are sampled from a real land/sea mask (lib/landMask.ts), so they form
// the actual continents. A true 3D rotation re-projects every point around the
// polar axis each frame (dots flow across the face and fade at the limb), over a
// softly-shaded ocean sphere + an atmosphere halo, with red hotspot markers at
// real cities. Theme-aware (tracks --fg); respects prefers-reduced-motion.
const GLOBE_CITIES: [number, number][] = [
  [40.7, -74.0],  // New York
  [51.5, -0.12],  // London
  [-23.5, -46.6], // São Paulo
  [39.9, 116.4],  // Beijing
  [-1.29, 36.82], // Nairobi
  [-33.9, 151.2], // Sydney
];

function DotGlobe({ className, size = 348 }: { className?: string; size?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const R = (size / 2) * 0.82; // leave room for the atmosphere halo
    const tilt = -0.36; // lean the north pole back
    const ct = Math.cos(tilt), st = Math.sin(tilt);
    const D2R = Math.PI / 180;
    const toXYZ = (lat: number, lon: number) => {
      const cla = Math.cos(lat * D2R);
      return { x: cla * Math.cos(lon * D2R), y: Math.sin(lat * D2R), z: cla * Math.sin(lon * D2R) };
    };

    // sample land points on an ~even grid (lon count ∝ cos(lat)), rows staggered
    const pts: { x: number; y: number; z: number }[] = [];
    const latStep = 2.6;
    for (let lat = -80; lat <= 84; lat += latStep) {
      const cr = Math.cos(lat * D2R);
      const lonCount = Math.max(8, Math.round(150 * cr));
      const off = (Math.round(lat / latStep) & 1) ? 0.5 : 0;
      for (let k = 0; k < lonCount; k++) {
        const lon = -180 + ((k + off) * 360) / lonCount;
        if (isLand(lat, lon)) pts.push(toXYZ(lat, lon));
      }
    }
    const markers = GLOBE_CITIES.map(([lat, lon]) => toXYZ(lat, lon));

    // theme-adaptive color (read --fg channels, refresh on theme change)
    let fg = "255,255,255";
    const readFg = () => {
      const v = getComputedStyle(document.documentElement).getPropertyValue("--fg").trim();
      if (v) fg = v.replace(/\s+/g, ",");
    };
    readFg();
    const mo = new MutationObserver(readFg);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "style", "data-theme"] });

    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    const SPEED = 0.18; // rad/s
    const start = performance.now();
    let raf = 0;

    const frame = (now: number) => {
      const spin = reduce ? 0.6 : ((now - start) / 1000) * SPEED;
      const cosA = Math.cos(spin), sinA = Math.sin(spin);
      ctx.clearRect(0, 0, size, size);

      // atmosphere halo
      const halo = ctx.createRadialGradient(cx, cy, R * 0.65, cx, cy, R * 1.22);
      halo.addColorStop(0, "rgba(56,189,248,0)");
      halo.addColorStop(0.72, "rgba(56,189,248,0.02)");
      halo.addColorStop(0.9, "rgba(56,189,248,0.16)");
      halo.addColorStop(1, "rgba(56,189,248,0)");
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.22, 0, 6.2832);
      ctx.fill();

      // shaded ocean sphere (light from upper-left)
      const ocean = ctx.createRadialGradient(cx - R * 0.32, cy - R * 0.34, R * 0.1, cx, cy, R);
      ocean.addColorStop(0, `rgba(${fg},0.12)`);
      ocean.addColorStop(0.7, `rgba(${fg},0.055)`);
      ocean.addColorStop(1, `rgba(${fg},0.015)`);
      ctx.fillStyle = ocean;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, 6.2832);
      ctx.fill();
      // crisp rim
      ctx.strokeStyle = `rgba(${fg},0.14)`;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, 6.2832);
      ctx.stroke();

      // land dots
      for (const p of pts) {
        const x = p.x * cosA + p.z * sinA; // rotate about polar axis
        const z = -p.x * sinA + p.z * cosA;
        const yy = p.y * ct - z * st; // tilt about X
        const zz = p.y * st + z * ct;
        if (zz < -0.02) continue; // front hemisphere
        ctx.beginPath();
        ctx.arc(cx + x * R, cy - yy * R, 1.15, 0, 6.2832);
        ctx.fillStyle = `rgba(${fg},${(0.3 + Math.max(0, zz) * 0.6).toFixed(3)})`;
        ctx.fill();
      }

      // hotspot markers
      for (let i = 0; i < markers.length; i++) {
        const p = markers[i];
        const x = p.x * cosA + p.z * sinA;
        const z = -p.x * sinA + p.z * cosA;
        const yy = p.y * ct - z * st;
        const zz = p.y * st + z * ct;
        if (zz < 0) continue; // behind the globe
        const mx = cx + x * R, my = cy - yy * R;
        const k = reduce ? 0.35 : (now / 2600 + i * 0.17) % 1; // expanding pulse
        ctx.beginPath();
        ctx.arc(mx, my, 3 + k * 8, 0, 6.2832);
        ctx.fillStyle = `rgba(244,63,94,${(0.42 * (1 - k)).toFixed(3)})`;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(mx, my, 2.4, 0, 6.2832);
        ctx.fillStyle = "rgba(244,63,94,0.95)";
        ctx.fill();
      }

      if (!reduce) raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      mo.disconnect();
    };
  }, [size]);

  return <canvas ref={ref} className={className} style={{ width: size, height: size }} aria-hidden="true" />;
}
