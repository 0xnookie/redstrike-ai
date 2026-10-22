"use client";

import { useMemo, useState } from "react";
import { ListChecks } from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx } from "@/lib/format";
import type { CoverageStatus, CoverageCategory } from "@/lib/types";
import { Card, PageHeader, Kpi, Pill, EmptyState } from "@/components/ui/primitives";

// Coverage statuses encode what the deterministic router decided for each vuln category.
const CS: Record<CoverageStatus, { label: string; color: string }> = {
  attempted: { label: "Attempted", color: "#22c55e" },
  pending: { label: "Pending", color: "#3b82f6" },
  blocked: { label: "Blocked", color: "#f59e0b" },
  skipped: { label: "Skipped", color: "#94a3b8" },
  "n/a": { label: "Out of phase", color: "#64748b" },
  pipeline: { label: "Pipeline", color: "#a78bfa" },
};
const ORDER: CoverageStatus[] = ["pending", "attempted", "blocked", "skipped", "pipeline", "n/a"];

export default function CoveragePage() {
  const { coverage } = useConsole();
  const [status, setStatus] = useState<string>("all");

  const cats = coverage?.categories ?? [];
  const tally = useMemo(() => {
    const t: Record<string, number> = {};
    for (const c of cats) t[c.status] = (t[c.status] ?? 0) + 1;
    return t;
  }, [cats]);

  if (!cats.length) {
    return (
      <>
        <PageHeader
          title="Coverage"
          subtitle="Which vulnerability categories were attempted, skipped with a reason, or left out of phase."
        />
        <EmptyState
          icon={<ListChecks size={28} />}
          title="No coverage ledger for this engagement"
          hint="Deterministic routing records which categories ran vs. were skipped-with-reason, so 'not attempted' is distinct from 'ran and found nothing'. redstrike run seeds it automatically; or generate it with scripts/coverage.py --plan --engagement <dir>."
        />
      </>
    );
  }

  const shown = cats.filter((c) => status === "all" || c.status === status);
  const withFindings = cats.filter((c) => (c.findings_count ?? 0) > 0).length;
  const phases = coverage?.active_phases?.join(" · ") || "—";

  return (
    <>
      <PageHeader
        title="Coverage"
        subtitle={`Deterministic routing ledger — ${cats.length} categories across ${phases}. "Not attempted" is a first-class, visible state.`}
      />

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Kpi label="Categories" value={cats.length} icon={<ListChecks size={15} />} />
        <Kpi label="Attempted" value={tally["attempted"] ?? 0} color="#22c55e" />
        <Kpi label="Skipped" value={tally["skipped"] ?? 0} color="#94a3b8" sub="with reason" />
        <Kpi label="Out of phase" value={tally["n/a"] ?? 0} />
        <Kpi
          label="Pending"
          value={tally["pending"] ?? 0}
          color={tally["pending"] ? "#3b82f6" : undefined}
          sub={tally["pending"] ? "not yet run" : undefined}
        />
        <Kpi label="With findings" value={withFindings} color="#f43f5e" />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        <Chip active={status === "all"} onClick={() => setStatus("all")} label={`All (${cats.length})`} />
        {ORDER.filter((s) => tally[s]).map((s) => (
          <Chip key={s} active={status === s} onClick={() => setStatus(s)} label={`${CS[s].label} (${tally[s]})`} />
        ))}
      </div>

      <Card className="divide-y divide-line">
        {shown.map((c) => (
          <Row key={c.id} c={c} />
        ))}
      </Card>
    </>
  );
}

function Row({ c }: { c: CoverageCategory }) {
  const m = CS[c.status] ?? CS.pending;
  const n = c.findings_count ?? 0;
  return (
    <div className="flex items-start gap-3 p-3.5">
      <div className="w-32 shrink-0">
        <Pill label={m.label} color={m.color} dot />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
          <span className="font-mono text-sm font-medium">{c.name || c.id}</span>
          <span className="text-[11px] uppercase tracking-wide text-muted">{c.phase}</span>
          {n > 0 && (
            <span className="text-[11px] font-medium" style={{ color: "#f43f5e" }}>
              {n} finding{n === 1 ? "" : "s"}
            </span>
          )}
        </div>
        {c.reason && <p className="mt-0.5 text-xs leading-relaxed text-muted">{c.reason}</p>}
      </div>
    </div>
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
