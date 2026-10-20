"use client";

import { useMemo, useState } from "react";
import { useConsole } from "@/lib/store";
import { VERDICT } from "@/lib/theme";
import { fmtDateTime, relTime, cx } from "@/lib/format";
import type { ActivityKind } from "@/lib/types";
import { Card, PageHeader, Pill, SeverityBadge } from "@/components/ui/primitives";
import { ACTIVITY_ICON } from "@/components/activityIcons";

const KIND_LABEL: Record<ActivityKind, string> = {
  recon: "Recon", tool_use: "Tool use", finding: "Finding", review: "Review",
  approval: "Approval", chain: "Chain", report: "Report", note: "Note",
};

export default function ActivityPage() {
  const { activity } = useConsole();
  const [filter, setFilter] = useState<ActivityKind | "all">("all");

  const kinds = useMemo(() => Array.from(new Set(activity.map((e) => e.kind))), [activity]);
  const events = useMemo(
    () => [...activity].sort((a, b) => +new Date(b.ts) - +new Date(a.ts)).filter((e) => filter === "all" || e.kind === filter),
    [activity, filter]
  );

  return (
    <>
      <PageHeader title="Activity" subtitle="Execution stream across the agent fleet — recon, findings, reviews, approvals and chains." />

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        <Chip active={filter === "all"} onClick={() => setFilter("all")} label={`All (${activity.length})`} />
        {kinds.map((k) => (
          <Chip key={k} active={filter === k} onClick={() => setFilter(k)} label={`${KIND_LABEL[k]} (${activity.filter((e) => e.kind === k).length})`} />
        ))}
      </div>

      <Card className="p-5">
        {events.length === 0 && (
          <p className="py-12 text-center text-sm text-muted">No activity yet — load an engagement with reviewed findings.</p>
        )}
        <ol className="relative">
          {/* vertical rail */}
          {events.length > 0 && <span className="absolute bottom-2 left-[15px] top-2 w-px bg-line" aria-hidden />}
          {events.map((e) => {
            const I = ACTIVITY_ICON[e.kind];
            return (
              <li key={e.id} className="relative flex gap-4 pb-6 last:pb-0">
                <div className="z-10 grid h-8 w-8 shrink-0 place-items-center rounded-full border border-line bg-card text-muted">
                  <I size={15} />
                </div>
                <div className="min-w-0 flex-1 pt-0.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-medium">{e.title}</span>
                    <span className="shrink-0 text-xs text-muted" title={fmtDateTime(e.ts)}>{relTime(e.ts)}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    <Pill label={KIND_LABEL[e.kind]} />
                    <span className="font-mono text-[11px] text-muted">{e.actor}</span>
                    {e.refId && <span className="font-mono text-[11px] text-brand">{e.refId}</span>}
                    {e.severity && <SeverityBadge severity={e.severity} dot={false} />}
                    {e.verdict && <Pill label={VERDICT[e.verdict].label} color={VERDICT[e.verdict].color} dot />}
                  </div>
                  {e.detail && <p className="mt-1.5 text-sm text-muted">{e.detail}</p>}
                </div>
              </li>
            );
          })}
        </ol>
      </Card>
    </>
  );
}

function Chip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cx(
        "rounded-full border px-2.5 py-1 text-xs font-medium transition",
        active ? "border-brand/60 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg"
      )}
    >
      {label}
    </button>
  );
}
