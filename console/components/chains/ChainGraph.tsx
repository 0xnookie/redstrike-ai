"use client";

import type { AttackChain, Finding } from "@/lib/types";
import { cvssScore } from "@/lib/cvss";
import { sevMeta, roleColor, hexA } from "@/lib/theme";

const NODE_W = 232, NODE_H = 104, GAP = 88, PAD = 28, LABEL_H = 34;

export function ChainGraph({
  chain, findingsById, onSelectFinding,
}: {
  chain: AttackChain;
  findingsById: Record<string, Finding>;
  onSelectFinding: (f: Finding) => void;
}) {
  const n = chain.steps.length;
  const width = PAD * 2 + n * NODE_W + (n - 1) * GAP;
  const height = PAD * 2 + NODE_H + LABEL_H;
  const cy = PAD + NODE_H / 2;
  const xOf = (i: number) => PAD + i * (NODE_W + GAP);

  return (
    <div className="graph-grid scroll-thin overflow-x-auto rounded-xl border border-line bg-card2">
      <div className="relative" style={{ width: Math.max(width, 320), height, minWidth: "100%" }}>
        {/* edges */}
        <svg className="absolute inset-0" width={width} height={height} style={{ pointerEvents: "none" }}>
          <defs>
            <marker id="arrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L7,3 L0,6 Z" fill="rgb(var(--muted))" />
            </marker>
          </defs>
          {chain.steps.slice(0, -1).map((s, i) => {
            const x1 = xOf(i) + NODE_W, x2 = xOf(i + 1);
            const mx = (x1 + x2) / 2;
            return (
              <g key={i}>
                <path
                  d={`M ${x1} ${cy} C ${mx} ${cy}, ${mx} ${cy}, ${x2} ${cy}`}
                  fill="none" stroke="rgb(var(--muted))" strokeWidth={1.5} strokeDasharray="4 4" markerEnd="url(#arrow)"
                />
                {s.enables && (
                  <text x={mx} y={cy - 10} textAnchor="middle" className="fill-muted" fontSize={10}>
                    {s.enables.length > 22 ? s.enables.slice(0, 21) + "…" : s.enables}
                  </text>
                )}
              </g>
            );
          })}
        </svg>

        {/* nodes */}
        {chain.steps.map((s, i) => {
          const f = findingsById[s.finding_id];
          const col = roleColor(s.role);
          const sev = f ? sevMeta(f.severity) : null;
          const score = f ? cvssScore(f.cvss_vector) : null;
          return (
            <button
              key={s.finding_id + i}
              onClick={() => f && onSelectFinding(f)}
              className="absolute flex flex-col rounded-xl border bg-card p-3 text-left shadow-card transition hover:shadow-pop"
              style={{ left: xOf(i), top: PAD, width: NODE_W, height: NODE_H, borderColor: hexA(col, "66") }}
            >
              <div className="flex items-center justify-between">
                <span className="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide" style={{ color: col, background: hexA(col, "1f") }}>
                  {s.role}
                </span>
                {sev && <span className="flex items-center gap-1 text-[10px] text-muted"><span className="h-2 w-2 rounded-full" style={{ background: sev.color }} />{sev.label}</span>}
              </div>
              <div className="mt-1.5 font-mono text-[11px] text-muted">{s.finding_id}</div>
              <div className="mt-0.5 line-clamp-2 text-xs font-medium leading-tight">{f ? f.title : "(finding not in set)"}</div>
              {score !== null && <div className="mt-auto pt-1 text-[11px] text-muted">CVSS <span className="tabular-nums" style={{ color: sev?.color }}>{score.toFixed(1)}</span></div>}
            </button>
          );
        })}
      </div>
    </div>
  );
}
