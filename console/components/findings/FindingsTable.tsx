"use client";

import { ShieldCheck } from "lucide-react";
import type { Finding } from "@/lib/types";
import { cvssScore } from "@/lib/cvss";
import { VERDICT, sevMeta, hexA } from "@/lib/theme";
import { cx, relTime, fmtDate, verdictOf } from "@/lib/format";
import { SeverityBadge, VerdictBadge } from "@/components/ui/primitives";

const TH = "px-4 py-2.5 text-left text-[10.5px] font-medium uppercase tracking-wide text-faint";

/** A CVSS base-score chip, tinted by the finding's severity (data color). */
function CvssChip({ score, severity }: { score: number | null; severity: Finding["severity"] }) {
  if (score === null) return <span className="font-mono text-xs text-faint">—</span>;
  const color = sevMeta(severity).color;
  return (
    <span
      className="inline-flex items-center rounded-md px-1.5 py-0.5 font-mono text-[11px] font-medium tabular-nums"
      style={{ color, background: hexA(color, "14"), border: `1px solid ${hexA(color, "44")}` }}
    >
      {score.toFixed(1)}
    </span>
  );
}

/** Pure, presentational findings table — rows are already filtered + sorted. */
export function FindingsTable({
  rows, onSelect, fresh,
}: { rows: Finding[]; onSelect: (f: Finding) => void; fresh?: Set<string> }) {
  return (
    <div className="scroll-thin overflow-x-auto">
      <table className="w-full min-w-[820px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-line">
            <th className={TH}>ID</th>
            <th className={TH}>Finding</th>
            <th className={TH}>Severity</th>
            <th className={TH}>CVSS</th>
            <th className={TH}>Status</th>
            <th className={TH}>Proof</th>
            <th className={cx(TH, "text-right")}>Found</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => {
            const score = cvssScore(f.cvss_vector);
            const v = verdictOf(f);
            const hasProof = (f.evidence?.length ?? 0) > 0;
            const found = f.review?.reviewed_at;
            return (
              <tr
                key={f.id}
                tabIndex={0}
                onClick={() => onSelect(f)}
                onKeyDown={(e) => { if (e.key === "Enter") onSelect(f); }}
                className={cx(
                  "cursor-pointer border-t border-line/70 outline-none transition hover:bg-fg/[0.03] focus-visible:bg-fg/[0.04]",
                  v === "rejected" && "opacity-50",
                  fresh?.has(f.id) && "row-flash", // just landed via live refresh
                )}
              >
                <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-muted" style={{ boxShadow: `inset 3px 0 0 ${sevMeta(f.severity).color}` }}>
                  {f.id}
                </td>
                <td className="max-w-sm px-4 py-3">
                  <div className="truncate text-fg">{f.title}</div>
                  <div className="truncate font-mono text-[11px] text-faint">{f.id} · {f.asset}</div>
                </td>
                <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                <td className="whitespace-nowrap px-4 py-3"><CvssChip score={score} severity={f.severity} /></td>
                <td className="px-4 py-3">{v ? <VerdictBadge verdict={v} /> : <span className="text-xs text-faint">—</span>}</td>
                <td className="px-4 py-3">
                  {hasProof ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-medium" style={{ color: VERDICT.accepted.color }} title={`${f.evidence.length} evidence item${f.evidence.length === 1 ? "" : "s"}`}>
                      <ShieldCheck size={13} /> {f.evidence.length}
                    </span>
                  ) : (
                    <span className="text-xs text-faint">—</span>
                  )}
                </td>
                <td className="whitespace-nowrap px-4 py-3 text-right font-mono text-[11px] text-faint" title={fmtDate(found)}>
                  {found ? relTime(found) : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length === 0 && <div className="py-14 text-center text-sm text-muted">No findings match the current filters.</div>}
    </div>
  );
}
